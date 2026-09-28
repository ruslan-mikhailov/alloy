package encryptedlogs

import (
	"context"
	"encoding/base64"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"sync"
	"strings"
	"testing"
	"time"

	"github.com/grafana/alloy/internal/component"
	"github.com/grafana/alloy/internal/component/common/loki"
	"github.com/grafana/alloy/internal/component/common/lokiprotect"
	"github.com/grafana/loki/pkg/push"
	"github.com/prometheus/common/model"
)

func testPolicies(t *testing.T) []lokiprotect.Policy {
	t.Helper()
	keyFile := filepath.Join(t.TempDir(), "master.key")
	if err := os.WriteFile(keyFile, []byte(base64.StdEncoding.EncodeToString([]byte("0123456789abcdef0123456789abcdef"))+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	return []lokiprotect.Policy{{Fields: []string{"label.namespace", "line.email"}, KeyFile: keyFile, ValueScheme: lokiprotect.Scheme}}
}

func testEntry(line string) loki.Entry {
	return loki.NewEntry(model.LabelSet{"namespace": "prod-blue", "service": "frontend"}, push.Entry{
		Line: line, StructuredMetadata: push.LabelsAdapter{{Name: "trace", Value: "abc123"}},
	})
}

func TestProtectEntryPreservesPublicLogfmtAndSource(t *testing.T) {
	p, err := lokiprotect.New(testPolicies(t))
	if err != nil {
		t.Fatal(err)
	}
	input := testEntry(`event=login email="alice@example.test" note="hello world" count=7`)
	output, err := protectEntry(p, input)
	if err != nil {
		t.Fatal(err)
	}
	if input.Labels["namespace"] != "prod-blue" || input.Line != `event=login email="alice@example.test" note="hello world" count=7` {
		t.Fatal("source entry was mutated")
	}
	if output.Labels["service"] != "frontend" || output.StructuredMetadata[0].Value != "abc123" ||
		output.Labels["namespace"] == "prod-blue" || !strings.HasPrefix(string(output.Labels["namespace"]), "lenc:v1:") {
		t.Fatalf("invalid protected labels or metadata: %#v", output)
	}
	if !strings.HasPrefix(output.Line, `event=login email="lenc:v1:`) || !strings.HasSuffix(output.Line, `" note="hello world" count=7`) || strings.Contains(output.Line, "alice@example.test") {
		t.Fatalf("line did not preserve public fields or seal email: %q", output.Line)
	}
	again, err := protectEntry(p, input)
	if err != nil || again.Line != output.Line || again.Labels["namespace"] != output.Labels["namespace"] {
		t.Fatal("same input did not produce the same ciphertext")
	}
}

func TestProtectEntryUsesSeparatePolicyKeys(t *testing.T) {
	policies := testPolicies(t)
	tokenFile := filepath.Join(t.TempDir(), "token.key")
	if err := os.WriteFile(tokenFile, []byte(base64.StdEncoding.EncodeToString([]byte("abcdefghijklmnopqrstuvwxyz012345"))), 0600); err != nil {
		t.Fatal(err)
	}
	policies = append(policies, lokiprotect.Policy{Fields: []string{"line.api_token"}, KeyFile: tokenFile, ValueScheme: lokiprotect.Scheme})
	p, err := lokiprotect.New(policies)
	if err != nil {
		t.Fatal(err)
	}
	output, err := protectEntry(p, testEntry(`event=login email=alice@example.test api_token=demo-123 outcome=accepted`))
	if err != nil {
		t.Fatal(err)
	}
	fields, err := parseLine(output.Line)
	if err != nil {
		t.Fatal(err)
	}
	values := make(map[string]string, len(fields))
	for _, field := range fields {
		values[field.name] = field.value
	}
	if values["outcome"] != "accepted" || values["event"] != "login" ||
		!strings.HasPrefix(values["email"], "lenc:v1:") || !strings.HasPrefix(values["api_token"], "lenc:v1:") ||
		strings.Split(values["email"], ":")[2] == strings.Split(values["api_token"], ":")[2] ||
		strings.Contains(output.Line, "demo-123") {
		t.Fatalf("separate policy protection failed: %q", output.Line)
	}
}

func TestProtectEntryDropsWholeInvalidEntry(t *testing.T) {
	p, err := lokiprotect.New(testPolicies(t))
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name string
		edit func(*loki.Entry)
	}{
		{"missing line field", func(e *loki.Entry) { e.Line = `event=login` }},
		{"empty selected line field", func(e *loki.Entry) { e.Line = `event=login email=""` }},
		{"missing label", func(e *loki.Entry) { delete(e.Labels, "namespace") }},
		{"duplicate line key", func(e *loki.Entry) { e.Line += ` email=other` }},
		{"bare token", func(e *loki.Entry) { e.Line += ` bare` }},
		{"malformed quoted value", func(e *loki.Entry) { e.Line = `email="unterminated` }},
		{"cross category name collision", func(e *loki.Entry) { e.Labels["email"] = "other" }},
		{"public line copy", func(e *loki.Entry) { e.Line += ` note="user alice@example.test"` }},
		{"public key copy", func(e *loki.Entry) { e.Line += ` alice@example.test=other` }},
		{"public label copy", func(e *loki.Entry) { e.Labels["other"] = "alice@example.test" }},
		{"metadata copy", func(e *loki.Entry) { e.StructuredMetadata[0].Value = "alice@example.test" }},
		{"metadata collision", func(e *loki.Entry) { e.StructuredMetadata[0].Name = "email" }},
		{"already encrypted", func(e *loki.Entry) { e.Line = `email=lenc:v1:fake` }},
		{"invalid utf8 selected value", func(e *loki.Entry) { e.Line = "email=\xff" }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			input := testEntry(`event=login email=alice@example.test`)
			tt.edit(&input)
			if _, err := protectEntry(p, input); err == nil {
				t.Fatalf("forwarded unsafe entry: %#v", input)
			}
		})
	}
}

func TestReceiverFanoutDropsInvalidBeforeValid(t *testing.T) {
	left := loki.NewLogsReceiver(loki.WithChannel(make(chan loki.Entry, 2)))
	right := loki.NewLogsReceiver(loki.WithChannel(make(chan loki.Entry, 2)))
	policies := testPolicies(t)
	policies[0].Fields = append(policies[0].Fields, "line.customer_email")
	var exports Exports
	c, err := New(component.Options{ID: "loki.encrypted_logs.test", OnStateChange: func(state component.Exports) { exports = state.(Exports) }}, Arguments{
		Policies: policies, ForwardTo: []loki.LogsReceiver{left, right},
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); _ = c.Run(ctx) }()
	defer func() { cancel(); <-done }()
	for _, e := range []loki.Entry{
		testEntry(`email=alice@example.test email=duplicate customer_email=selected`),
		func() loki.Entry {
			e := testEntry(`event=login email=alice@example.test customer_email=selected`)
			e.Parsed = push.LabelsAdapter{{Name: "email", Value: "alice@example.test"}}
			return e
		}(),
		testEntry(`event=login email=alice@example.test customer_email=selected customer.email=other`),
		testEntry(`event=login email=alice@example.test customer_email=selected`),
	} {
		select {
		case exports.Receiver.Chan() <- e:
		case <-time.After(3 * time.Second):
			t.Fatal("receiver did not accept entry")
		}
	}
	for _, recv := range []loki.LogsReceiver{left, right} {
		select {
		case entry := <-recv.Chan():
			if entry.Labels["namespace"] == "prod-blue" || strings.Contains(entry.Line, "alice@example.test") ||
				strings.Contains(entry.Line, "customer_email=selected") || !strings.HasPrefix(entry.Line, "event=login email=lenc:v1:") ||
				!strings.Contains(entry.Line, " customer_email=lenc:v1:") {
				t.Fatalf("fanout received plaintext or malformed entry: %#v", entry)
			}
		case <-time.After(3 * time.Second):
			t.Fatal("valid entry was not forwarded")
		}
		select {
		case extra := <-recv.Chan():
			t.Fatalf("invalid entry leaked to fanout: %#v", extra)
		default:
		}
	}
}

func TestProtectStructuredMetadataWithoutMutatingInput(t *testing.T) {
	policies := testPolicies(t)
	policies[0].Fields = append(policies[0].Fields, "metadata.customer_email")
	p, err := lokiprotect.New(policies)
	if err != nil {
		t.Fatal(err)
	}
	input := testEntry(`event=login email=alice@example.test`)
	input.StructuredMetadata = append(input.StructuredMetadata, push.LabelAdapter{Name: "customer_email", Value: "bob@example.test"})
	output, err := protectEntry(p, input)
	if err != nil {
		t.Fatal(err)
	}
	if input.StructuredMetadata[1].Value != "bob@example.test" ||
		output.StructuredMetadata[0].Value != "abc123" ||
		!strings.HasPrefix(output.StructuredMetadata[1].Value, "lenc:v1:") {
		t.Fatalf("metadata protection mutated source or failed to seal: %#v", output.StructuredMetadata)
	}
	input.StructuredMetadata = input.StructuredMetadata[:1]
	if _, err := protectEntry(p, input); err == nil {
		t.Fatal("missing selected metadata was accepted")
	}
	input.StructuredMetadata = append(input.StructuredMetadata, push.LabelAdapter{Name: "customer_email", Value: "bob@example.test"})
	input.StructuredMetadata = append(input.StructuredMetadata, push.LabelAdapter{Name: "customer_email", Value: "duplicate"})
	if _, err := protectEntry(p, input); err == nil {
		t.Fatal("duplicate selected metadata was accepted")
	}
}

func TestRejectAmbiguousPolicyFields(t *testing.T) {
	policies := testPolicies(t)
	policies[0].Fields = append(policies[0].Fields, "label.email")
	if err := validatePolicies(policies); err == nil {
		t.Fatal("accepted selected name in two categories")
	}
}

func TestProtectEntryRejectsParsedWithoutMutation(t *testing.T) {
	p, err := lokiprotect.New(testPolicies(t))
	if err != nil {
		t.Fatal(err)
	}
	input := testEntry(`event=login email=alice@example.test`)
	input.Parsed = push.LabelsAdapter{{Name: "email", Value: "alice@example.test"}}
	original := input
	original.Labels = input.Labels.Clone()
	original.StructuredMetadata = slices.Clone(input.StructuredMetadata)
	original.Parsed = slices.Clone(input.Parsed)
	if _, err := protectEntry(p, input); err == nil {
		t.Fatal("entry with uninspected parsed fields was accepted")
	}
	if !reflect.DeepEqual(input, original) {
		t.Fatal("rejected entry was mutated")
	}
}

func TestProtectEntryRejectsNormalizedSelectedAliases(t *testing.T) {
	for _, tt := range []struct {
		name   string
		field  string
		alter  func(*loki.Entry)
	}{
		{"logfmt key", "line.customer_email", func(e *loki.Entry) {
			e.Line = `email=alice@example.test customer_email=selected customer.email=other`
		}},
		{"metadata key", "metadata.customer_email", func(e *loki.Entry) {
			e.StructuredMetadata = append(e.StructuredMetadata,
				push.LabelAdapter{Name: "customer_email", Value: "selected"},
				push.LabelAdapter{Name: "customer.email", Value: "other"})
		}},
		{"label key", "label.customer_email", func(e *loki.Entry) {
			e.Labels["customer_email"] = "selected"
			e.Labels["customer.email"] = "other"
		}},
		{"cross-carrier key", "line.customer_email", func(e *loki.Entry) {
			e.Line = `email=alice@example.test customer_email=selected`
			e.StructuredMetadata = append(e.StructuredMetadata, push.LabelAdapter{Name: "customer.email", Value: "other"})
		}},
		{"unicode key", "line.customer_email", func(e *loki.Entry) {
			e.Line = `email=alice@example.test customer_email=selected customer☃email=other`
		}},
		{"numeric prefix", "line._123", func(e *loki.Entry) {
			e.Line = `email=alice@example.test _123=selected 123=other`
		}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			policies := testPolicies(t)
			policies[0].Fields = append(policies[0].Fields, tt.field)
			p, err := lokiprotect.New(policies)
			if err != nil {
				t.Fatal(err)
			}
			input := testEntry(`email=alice@example.test`)
			tt.alter(&input)
			original := input
			original.Labels = input.Labels.Clone()
			original.StructuredMetadata = slices.Clone(input.StructuredMetadata)
			if _, err := protectEntry(p, input); err == nil {
				t.Fatal("normalized alias of selected field was accepted")
			}
			if !reflect.DeepEqual(input, original) {
				t.Fatal("rejected alias entry was mutated")
			}
		})
	}
}

func TestProtectEntryAllowsDistinctNormalizedPublicFields(t *testing.T) {
	policies := testPolicies(t)
	policies[0].Fields = append(policies[0].Fields, "line.customer_email")
	p, err := lokiprotect.New(policies)
	if err != nil {
		t.Fatal(err)
	}
	input := testEntry(`email=alice@example.test customer_email=selected customer.email_extra=public`)
	input.StructuredMetadata = append(input.StructuredMetadata, push.LabelAdapter{Name: "customer.email_extra", Value: "public"})
	output, err := protectEntry(p, input)
	if err != nil {
		t.Fatal(err)
	}
	if input.Line != `email=alice@example.test customer_email=selected customer.email_extra=public` ||
		!strings.Contains(output.Line, " customer_email=lenc:v1:") ||
		!strings.HasSuffix(output.Line, " customer.email_extra=public") ||
		output.StructuredMetadata[1] != input.StructuredMetadata[1] {
		t.Fatal("distinct public field changed or selected field was not protected")
	}
}

type notifiedReceiver struct {
	entries chan loki.Entry
	called  chan struct{}
	once    sync.Once
}

func (r *notifiedReceiver) Chan() chan loki.Entry {
	r.once.Do(func() { close(r.called) })
	return r.entries
}

func TestReloadKeepsPolicyAndDestinationTogether(t *testing.T) {
	oldDestination := &notifiedReceiver{entries: make(chan loki.Entry), called: make(chan struct{})}
	newDestination := loki.NewLogsReceiver(loki.WithChannel(make(chan loki.Entry, 1)))
	oldPolicies := testPolicies(t)
	var exports Exports
	c, err := New(component.Options{ID: "loki.encrypted_logs.reload", OnStateChange: func(state component.Exports) {
		exports = state.(Exports)
	}}, Arguments{Policies: oldPolicies, ForwardTo: []loki.LogsReceiver{oldDestination}})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); _ = c.Run(ctx) }()
	defer func() { cancel(); <-done }()

	line := `email=alice@example.test api_token=secret-123`
	select {
	case exports.Receiver.Chan() <- testEntry(line):
	case <-time.After(3 * time.Second):
		t.Fatal("receiver did not accept first entry")
	}
	// Chan is called by Send before it attempts the unbuffered delivery.
	select {
	case <-oldDestination.called:
	case <-time.After(3 * time.Second):
		t.Fatal("first send did not reach the old destination")
	}

	newPolicies := testPolicies(t)
	newPolicies[0].Fields = append(newPolicies[0].Fields, "line.api_token")
	updateDone := make(chan error, 1)
	updateStarted := make(chan struct{})
	go func() {
		close(updateStarted)
		updateDone <- c.Update(Arguments{Policies: newPolicies, ForwardTo: []loki.LogsReceiver{newDestination}})
	}()
	<-updateStarted
	select {
	case err := <-updateDone:
		t.Fatalf("reload completed before old-policy send finished: %v", err)
	case <-time.After(100 * time.Millisecond):
	}

	select {
	case entry := <-oldDestination.entries:
		if !strings.HasPrefix(entry.Line, "email=lenc:v1:") || !strings.Contains(entry.Line, "api_token=secret-123") {
			t.Fatalf("old destination did not receive entry protected with old policy: %q", entry.Line)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("old-policy send stalled")
	}
	select {
	case err := <-updateDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("reload remained blocked after send")
	}
	select {
	case entry := <-newDestination.Chan():
		t.Fatalf("old-policy entry reached new destination: %#v", entry)
	default:
	}
	select {
	case exports.Receiver.Chan() <- testEntry(line):
	case <-time.After(3 * time.Second):
		t.Fatal("receiver did not accept updated entry")
	}
	select {
	case entry := <-newDestination.Chan():
		if strings.Contains(entry.Line, "alice@example.test") || strings.Contains(entry.Line, "secret-123") ||
			!strings.Contains(entry.Line, "email=lenc:v1:") || !strings.Contains(entry.Line, "api_token=lenc:v1:") {
			t.Fatalf("updated policy did not protect new destination: %q", entry.Line)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("updated destination did not receive entry")
	}
}
