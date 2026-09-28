package encryptedlogsprocessor

import (
	"context"
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"

	"github.com/grafana/alloy/internal/component/common/lokiprotect"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/confmap"
	"go.opentelemetry.io/collector/consumer"
	"go.opentelemetry.io/collector/consumer/consumertest"
	"go.opentelemetry.io/collector/pdata/plog"
	"go.opentelemetry.io/collector/processor"
	"go.opentelemetry.io/collector/receiver"
)

func fixtureKey(t *testing.T, start byte) string {
	t.Helper()
	key := make([]byte, 32)
	for i := range key {
		key[i] = start + byte(i)
	}
	file := filepath.Join(t.TempDir(), "master")
	require.NoError(t, os.WriteFile(file, []byte(base64.StdEncoding.EncodeToString(key)+"\n"), 0o600))
	return file
}

func fixtureConfig(t *testing.T) *Config {
	t.Helper()
	first, second := fixtureKey(t, 0), fixtureKey(t, 32)
	// Use the Collector's actual mapstructure configuration path, not struct
	// literals, so field names match collector YAML keys.
	var cfg Config
	err := confmap.NewFromStringMap(map[string]any{"policies": []any{
		map[string]any{"fields": []string{"label.namespace", "line.email", "metadata.customer_email"}, "key_file": first, "value_scheme": lokiprotect.Scheme},
		map[string]any{"fields": []string{"line.api_token"}, "key_file": second, "value_scheme": lokiprotect.Scheme},
	}}).Unmarshal(&cfg)
	require.NoError(t, err)
	require.NoError(t, cfg.Validate())
	return &cfg
}

func fixtureLogs(body string) plog.Logs {
	logs := plog.NewLogs()
	resource := logs.ResourceLogs().AppendEmpty()
	resource.Resource().Attributes().PutStr("namespace", "team-a")
	scope := resource.ScopeLogs().AppendEmpty()
	record := scope.LogRecords().AppendEmpty()
	record.Body().SetStr(body)
	record.Attributes().PutStr("customer_email", "customer@example.invalid")
	return logs
}

// A receiver invokes the configured Collector processor and stores the actual
// consumer's result; this tests the same Logs interface used by pipelines.
// Start propagates failures to the receiver, never to the next consumer.
type fixtureReceiver struct {
	next consumer.Logs
	logs plog.Logs
}

func (r *fixtureReceiver) Start(ctx context.Context, _ component.Host) error {
	return r.next.ConsumeLogs(ctx, r.logs)
}
func (r *fixtureReceiver) Shutdown(context.Context) error { return nil }

func receiverPipeline(t *testing.T, cfg *Config, logs plog.Logs) (*fixtureReceiver, *consumertest.LogsSink) {
	t.Helper()
	sink := &consumertest.LogsSink{}
	factory := NewFactory()
	p, err := factory.CreateLogs(context.Background(), processor.Settings{ID: component.MustNewID(TypeStr)}, cfg, sink)
	require.NoError(t, err)
	require.True(t, p.Capabilities().MutatesData)
	receiverFactory := receiver.NewFactory(component.MustNewType("fixture_logs"), func() component.Config { return &Config{} },
		receiver.WithLogs(func(_ context.Context, _ receiver.Settings, _ component.Config, next consumer.Logs) (receiver.Logs, error) {
			return &fixtureReceiver{next: next, logs: logs}, nil
		}, component.StabilityLevelAlpha))
	upstream, err := receiverFactory.CreateLogs(context.Background(), receiver.Settings{ID: component.MustNewID("fixture_logs")}, &Config{}, p)
	require.NoError(t, err)
	return upstream.(*fixtureReceiver), sink
}

func TestReceiverEncryptsTwoPoliciesBeforeConsumer(t *testing.T) {
	cfg := fixtureConfig(t)
	logs := fixtureLogs(`event=login email="alice@example.invalid" api_token=secret remaining="other value"`)
	incoming := logs.ResourceLogs().At(0).ScopeLogs().At(0).LogRecords().At(0)
	upstream, sink := receiverPipeline(t, cfg, logs)
	require.NoError(t, upstream.Start(context.Background(), nil))
	require.Equal(t, 1, sink.LogRecordCount())
	require.Len(t, sink.AllLogs(), 1)

	protector, err := lokiprotect.New(cfg.Policies)
	require.NoError(t, err)
	expectedLabel, err := protector.Seal("label.namespace", "team-a")
	require.NoError(t, err)
	expectedEmail, err := protector.Seal("line.email", "alice@example.invalid")
	require.NoError(t, err)
	expectedToken, err := protector.Seal("line.api_token", "secret")
	require.NoError(t, err)
	expectedMetadata, err := protector.Seal("metadata.customer_email", "customer@example.invalid")
	require.NoError(t, err)
	require.Equal(t, "lenc:v1:630dcd2966c4336691125448bbb25b4f:kIAS6bsREGxxOaHcIg83QMuD1Kmm4efCubuxwDkrv6b4TbuaeA", expectedEmail)
	resource := logs.ResourceLogs().At(0)
	label, ok := resource.Resource().Attributes().Get("namespace")
	require.True(t, ok)
	require.Equal(t, expectedLabel, label.Str())
	meta, ok := incoming.Attributes().Get("customer_email")
	require.True(t, ok)
	require.Equal(t, expectedMetadata, meta.Str())
	require.Equal(t, `event=login email=`+expectedEmail+` api_token=`+expectedToken+` remaining="other value"`, incoming.Body().Str())
	require.NotEqual(t, expectedToken, expectedEmail)
	for _, original := range []string{"alice@example.invalid", "customer@example.invalid", "team-a", "secret"} {
		require.NotContains(t, incoming.Body().Str(), original)
	}
}

func TestReceiverRejectsWholeBatchWithoutMutationOrForwarding(t *testing.T) {
	cfg := fixtureConfig(t)
	for _, tc := range []struct {
		name   string
		change func(plog.Logs)
	}{
		{"missing line key", func(data plog.Logs) { record(data, 1).Body().SetStr("event=login email=bob@example.invalid") }},
		{"duplicate line key", func(data plog.Logs) { record(data, 1).Body().SetStr("event=login email=bob@example.invalid api_token=secret email=again") }},
		{"ambiguous logfmt", func(data plog.Logs) { record(data, 1).Body().SetStr("login email=bob@example.invalid api_token=secret") }},
		{"unterminated quote", func(data plog.Logs) { record(data, 1).Body().SetStr(`event=login email="bob@example.invalid api_token=secret`) }},
		{"already encrypted", func(data plog.Logs) { record(data, 1).Body().SetStr("event=login email=lenc:v1:presealed api_token=secret") }},
		{"missing metadata", func(data plog.Logs) { record(data, 1).Attributes().Remove("customer_email") }},
		{"wrong metadata type", func(data plog.Logs) { record(data, 1).Attributes().PutInt("customer_email", 4) }},
		{"already encrypted metadata", func(data plog.Logs) { record(data, 1).Attributes().PutStr("customer_email", "lenc:v1:presealed") }},
		{"missing label", func(data plog.Logs) { data.ResourceLogs().At(0).Resource().Attributes().Remove("namespace") }},
		{"already encrypted label", func(data plog.Logs) { data.ResourceLogs().At(0).Resource().Attributes().PutStr("namespace", "lenc:v1:presealed") }},
		{"record label copy", func(data plog.Logs) { record(data, 1).Attributes().PutStr("namespace", "team-a") }},
		{"resource line copy", func(data plog.Logs) { data.ResourceLogs().At(0).Resource().Attributes().PutStr("email", "bob@example.invalid") }},
		{"resource metadata copy", func(data plog.Logs) { data.ResourceLogs().At(0).Resource().Attributes().PutStr("customer_email", "customer2@example.invalid") }},
		{"scope plaintext copy", func(data plog.Logs) { data.ResourceLogs().At(0).ScopeLogs().At(0).Scope().Attributes().PutStr("other", "prefix-bob@example.invalid") }},
		{"scope selected name", func(data plog.Logs) { data.ResourceLogs().At(0).ScopeLogs().At(0).Scope().Attributes().PutStr("api_token", "secret") }},
		{"body plaintext copy", func(data plog.Logs) { record(data, 1).Body().SetStr("event=login email=bob@example.invalid api_token=secret other=prefix-bob@example.invalid") }},
		{"attribute plaintext copy", func(data plog.Logs) { record(data, 1).Attributes().PutStr("other", "prefix-secret-suffix") }},
		{"resource plaintext copy", func(data plog.Logs) { data.ResourceLogs().At(0).Resource().Attributes().PutStr("other", "prefix-customer2@example.invalid") }},
		{"line key plaintext copy", func(data plog.Logs) { record(data, 1).Body().SetStr("event=login email=bob@example.invalid api_token=secret bob@example.invalid=present") }},
		{"selected field name plaintext", func(data plog.Logs) { record(data, 1).Body().SetStr("event=login email=email api_token=secret") }},
		{"unsupported body", func(data plog.Logs) { record(data, 1).Body().SetInt(4) }},
		{"nested attribute", func(data plog.Logs) { record(data, 1).Attributes().PutEmptySlice("other").AppendEmpty().SetStr("secret") }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			logs := fixtureLogs("event=login email=alice@example.invalid api_token=secret")
			second := logs.ResourceLogs().At(0).ScopeLogs().At(0).LogRecords().AppendEmpty()
			second.Body().SetStr("event=login email=bob@example.invalid api_token=secret")
			second.Attributes().PutStr("customer_email", "customer2@example.invalid")
			tc.change(logs)
			before, err := (&plog.JSONMarshaler{}).MarshalLogs(logs)
			require.NoError(t, err)
			upstream, sink := receiverPipeline(t, cfg, logs)
			err = upstream.Start(context.Background(), nil)
			require.Error(t, err)
			require.NotContains(t, err.Error(), "bob@example.invalid")
			require.NotContains(t, err.Error(), "secret")
			require.Equal(t, 0, sink.LogRecordCount())
			after, marshalErr := (&plog.JSONMarshaler{}).MarshalLogs(logs)
			require.NoError(t, marshalErr)
			require.JSONEq(t, string(before), string(after))
		})
	}
}

func TestOTLPPreflightRejectsAliasesCopiesAndGeneratedFields(t *testing.T) {
	for _, tc := range []struct {
		name   string
		fields []string
		body   string
		change func(plog.Logs)
	}{
		{"record attribute alias", []string{"metadata.customer_email"}, "event=login", func(logs plog.Logs) {
			record(logs, 0).Attributes().PutStr("customer.email", "other@example.invalid")
		}},
		{"resource attribute alias", []string{"label.name_space"}, "event=login", func(logs plog.Logs) {
			logs.ResourceLogs().At(0).Resource().Attributes().PutStr("name_space", "team-a")
			logs.ResourceLogs().At(0).Resource().Attributes().PutStr("name.space", "other")
		}},
		{"scope attribute alias", []string{"metadata.customer_email"}, "event=login", func(logs plog.Logs) {
			logs.ResourceLogs().At(0).ScopeLogs().At(0).Scope().Attributes().PutStr("customer.email", "other")
		}},
		{"logfmt alias", []string{"line.customer_email"}, "customer_email=alice@example.invalid customer.email=bob@example.invalid", nil},
		{"escaped body copy without line policy", []string{"metadata.customer_email"}, `customer_email="customer\u0040example.invalid"`, nil},
		{"decoded body copy without line policy", []string{"metadata.customer_email"}, `other="customer\u0040example.invalid"`, nil},
		{"body selected name without line policy", []string{"metadata.customer_email"}, "customer_email=other@example.invalid", nil},
		{"generated event name", []string{"metadata.event_name"}, "event=login", func(logs plog.Logs) {
			record(logs, 0).Attributes().PutStr("event_name", "protected")
			record(logs, 0).SetEventName("other-sensitive")
		}},
		{"generated severity text", []string{"metadata.severity_text"}, "event=login", func(logs plog.Logs) {
			record(logs, 0).Attributes().PutStr("severity_text", "protected")
			record(logs, 0).SetSeverityText("other-sensitive")
		}},
		{"generated scope name", []string{"metadata.scope_name"}, "event=login", func(logs plog.Logs) {
			record(logs, 0).Attributes().PutStr("scope_name", "protected")
			logs.ResourceLogs().At(0).ScopeLogs().At(0).Scope().SetName("other-sensitive")
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &Config{Policies: []lokiprotect.Policy{{Fields: tc.fields, KeyFile: fixtureKey(t, 0), ValueScheme: lokiprotect.Scheme}}}
			logs := fixtureLogs(tc.body)
			if tc.change != nil {
				tc.change(logs)
			}
			before, err := (&plog.JSONMarshaler{}).MarshalLogs(logs)
			require.NoError(t, err)
			upstream, sink := receiverPipeline(t, cfg, logs)
			require.Error(t, upstream.Start(context.Background(), nil))
			require.Zero(t, sink.LogRecordCount())
			after, err := (&plog.JSONMarshaler{}).MarshalLogs(logs)
			require.NoError(t, err)
			require.JSONEq(t, string(before), string(after))
		})
	}
}

func TestOTLPWireDuplicateAttributesRejectAtomically(t *testing.T) {
	for _, tc := range []struct {
		name, field, resource, attributes string
	}{
		{"resource", "label.namespace", `"attributes":[{"key":"namespace","value":{"stringValue":"team-a"}},{"key":"namespace","value":{"stringValue":"team-b"}}]`, `"attributes":[]`},
		{"record", "metadata.customer_email", `"attributes":[]`, `"attributes":[{"key":"customer_email","value":{"stringValue":"alice@example.invalid"}},{"key":"customer_email","value":{"stringValue":"bob@example.invalid"}}]`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			wire := `{"resourceLogs":[{"resource":{` + tc.resource + `},"scopeLogs":[{"logRecords":[{"body":{"stringValue":"event=login"},` + tc.attributes + `}]}]}]}`
			logs, err := (&plog.JSONUnmarshaler{}).UnmarshalLogs([]byte(wire))
			require.NoError(t, err)
			attributes := record(logs, 0).Attributes()
			if tc.name == "resource" {
				attributes = logs.ResourceLogs().At(0).Resource().Attributes()
			}
			require.Equal(t, 2, attributes.Len(), "wire duplicate must survive pdata decoding")
			before, err := (&plog.JSONMarshaler{}).MarshalLogs(logs)
			require.NoError(t, err)
			cfg := &Config{Policies: []lokiprotect.Policy{{Fields: []string{tc.field}, KeyFile: fixtureKey(t, 0), ValueScheme: lokiprotect.Scheme}}}
			upstream, sink := receiverPipeline(t, cfg, logs)
			require.Error(t, upstream.Start(context.Background(), nil))
			require.Zero(t, sink.LogRecordCount())
			after, err := (&plog.JSONMarshaler{}).MarshalLogs(logs)
			require.NoError(t, err)
			require.JSONEq(t, string(before), string(after))
		})
	}
}

func TestOTLPLateDecodedCopyRejectsEarlierMutations(t *testing.T) {
	cfg := &Config{Policies: []lokiprotect.Policy{{Fields: []string{"metadata.customer_email"}, KeyFile: fixtureKey(t, 0), ValueScheme: lokiprotect.Scheme}}}
	logs := fixtureLogs("event=login")
	second := logs.ResourceLogs().At(0).ScopeLogs().At(0).LogRecords().AppendEmpty()
	second.Attributes().PutStr("customer_email", "customer@example.invalid")
	second.Body().SetStr(`other="customer\u0040example.invalid"`)
	before, err := (&plog.JSONMarshaler{}).MarshalLogs(logs)
	require.NoError(t, err)
	upstream, sink := receiverPipeline(t, cfg, logs)
	require.Error(t, upstream.Start(context.Background(), nil))
	require.Zero(t, sink.LogRecordCount())
	after, err := (&plog.JSONMarshaler{}).MarshalLogs(logs)
	require.NoError(t, err)
	require.JSONEq(t, string(before), string(after))
}

func TestOTLPMetadataOnlyPreservesSafeLogfmtBody(t *testing.T) {
	cfg := &Config{Policies: []lokiprotect.Policy{{Fields: []string{"metadata.customer_email"}, KeyFile: fixtureKey(t, 0), ValueScheme: lokiprotect.Scheme}}}
	const body = `event=login note="not customer data"`
	logs := fixtureLogs(body)
	upstream, sink := receiverPipeline(t, cfg, logs)
	require.NoError(t, upstream.Start(context.Background(), nil))
	require.Equal(t, 1, sink.LogRecordCount())
	require.Equal(t, body, record(logs, 0).Body().Str())
	value, ok := record(logs, 0).Attributes().Get("customer_email")
	require.True(t, ok)
	protector, err := lokiprotect.New(cfg.Policies)
	require.NoError(t, err)
	sealed, err := protector.Seal("metadata.customer_email", "customer@example.invalid")
	require.NoError(t, err)
	require.Equal(t, sealed, value.Str())
}

func TestOTLPJSONQuotedLogfmtValuesEncrypt(t *testing.T) {
	for _, tc := range []struct{ body, plaintext string }{
		{`path="a\/b"`, "a/b"},
		{`path="\ud83d\ude00"`, "😀"},
	} {
		t.Run(tc.body, func(t *testing.T) {
			cfg := &Config{Policies: []lokiprotect.Policy{{Fields: []string{"line.path"}, KeyFile: fixtureKey(t, 0), ValueScheme: lokiprotect.Scheme}}}
			logs := fixtureLogs(tc.body)
			upstream, sink := receiverPipeline(t, cfg, logs)
			require.NoError(t, upstream.Start(context.Background(), nil))
			require.Equal(t, 1, sink.LogRecordCount())
			protector, err := lokiprotect.New(cfg.Policies)
			require.NoError(t, err)
			sealed, err := protector.Seal("line.path", tc.plaintext)
			require.NoError(t, err)
			require.Equal(t, "path="+sealed, record(logs, 0).Body().Str())
		})
	}
}

func record(logs plog.Logs, index int) plog.LogRecord {
	return logs.ResourceLogs().At(0).ScopeLogs().At(0).LogRecords().At(index)
}

func TestPolicyValidationAndKeyFailures(t *testing.T) {
	cfg := fixtureConfig(t)
	for _, policies := range [][]lokiprotect.Policy{
		nil,
		{{Fields: []string{"body.email"}, KeyFile: cfg.Policies[0].KeyFile, ValueScheme: lokiprotect.Scheme}},
		{{Fields: []string{"line.email", "metadata.email"}, KeyFile: cfg.Policies[0].KeyFile, ValueScheme: lokiprotect.Scheme}},
		{{Fields: []string{"line.email", "line.email"}, KeyFile: cfg.Policies[0].KeyFile, ValueScheme: lokiprotect.Scheme}},
		{{Fields: []string{"metadata.customer__email"}, KeyFile: cfg.Policies[0].KeyFile, ValueScheme: lokiprotect.Scheme}},
		{{Fields: []string{"line.email"}, KeyFile: cfg.Policies[0].KeyFile, ValueScheme: "invalid"}},
	} {
		require.Error(t, (&Config{Policies: policies}).Validate())
	}
	bad := fixtureKey(t, 0)
	require.NoError(t, os.WriteFile(bad, []byte("bad-key"), 0o600))
	cfg.Policies[1].KeyFile = bad
	got, err := createLogsProcessor(context.Background(), processor.Settings{}, cfg, &consumertest.LogsSink{})
	require.Nil(t, got)
	require.ErrorContains(t, err, "policy 1")
	require.NotContains(t, err.Error(), "bad-key")
	cfg.Policies[1].KeyFile = filepath.Join(t.TempDir(), "missing")
	got, err = createLogsProcessor(context.Background(), processor.Settings{}, cfg, &consumertest.LogsSink{})
	require.Nil(t, got)
	require.Error(t, err)
}
