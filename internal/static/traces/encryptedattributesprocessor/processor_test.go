package encryptedattributesprocessor

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/collector/consumer"
	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/ptrace"
	"go.opentelemetry.io/collector/processor"
)

const (
	fixtureKey      = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8="
	fixtureOtherKey = "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY="
	fixtureABC      = "enc:v1:630dcd2966c4336691125448bbb25b4f:7aUwjY5fPtHvu_dUnzcxBJc6XQ"
	fixtureEmpty    = "enc:v1:630dcd2966c4336691125448bbb25b4f:l4ghA-S-aF9uZIBVXGBXsA"
	fixtureTokenABC = "enc:v1:630dcd2966c4336691125448bbb25b4f:Tmlsk4UeuIxW4e8k0i4OmCaSPg"
)

type recordingConsumer struct {
	calls  int
	traces ptrace.Traces
	err    error
}

func (*recordingConsumer) Capabilities() consumer.Capabilities { return consumer.Capabilities{} }

func (r *recordingConsumer) ConsumeTraces(_ context.Context, td ptrace.Traces) error {
	r.calls++
	r.traces = td
	return r.err
}

func testProcessor(t *testing.T, next consumer.Traces, names ...string) *encryptedProcessor {
	t.Helper()
	keyFile := filepath.Join(t.TempDir(), "key")
	require.NoError(t, os.WriteFile(keyFile, []byte(fixtureKey), 0600))
	enc, err := newEncryptor(keyFile, "aes256siv-hkdf-v1")
	require.NoError(t, err)
	return newProcessor(next, &Config{Policies: []Policy{{SpanAttributes: names}}}, []*encryptor{enc})
}

// Two resource/scope groups force failures after an earlier span has already
// been sealed, rather than testing only the first item in a batch.
func twoSpanBatch() ptrace.Traces {
	td := ptrace.NewTraces()
	for _, value := range []string{"abc", "second"} {
		resource := td.ResourceSpans().AppendEmpty()
		resource.Resource().Attributes().PutStr("password", "resource-plain")
		resource.Resource().Attributes().PutStr("resource.other", "unchanged")
		scope := resource.ScopeSpans().AppendEmpty()
		scope.Scope().Attributes().PutStr("password", "scope-plain")
		span := scope.Spans().AppendEmpty()
		span.SetName("test-span")
		span.Attributes().PutStr("password", value)
		span.Attributes().PutInt("span.other", 42)
		span.Events().AppendEmpty().Attributes().PutStr("password", "event-plain")
		span.Links().AppendEmpty().Attributes().PutStr("password", "link-plain")
	}
	return td
}

func secondSpan(td ptrace.Traces) ptrace.Span {
	return td.ResourceSpans().At(1).ScopeSpans().At(0).Spans().At(0)
}

func traceBytes(t *testing.T, td ptrace.Traces) []byte {
	t.Helper()
	b, err := (&ptrace.JSONMarshaler{}).MarshalTraces(td)
	require.NoError(t, err)
	return b
}

func TestConsumeTracesAtomicPreflight(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(ptrace.Traces)
	}{
		{"resource reserved", func(td ptrace.Traces) {
			td.ResourceSpans().At(1).Resource().Attributes().PutStr("enc.other", "occupied")
		}},
		{"scope reserved", func(td ptrace.Traces) {
			td.ResourceSpans().At(1).ScopeSpans().At(0).Scope().Attributes().PutStr("enc.other", "occupied")
		}},
		{"span reserved", func(td ptrace.Traces) {
			secondSpan(td).Attributes().PutStr("enc.password", "occupied")
		}},
		{"event reserved", func(td ptrace.Traces) {
			secondSpan(td).Events().At(0).Attributes().PutStr("enc.other", "occupied")
		}},
		{"event reserved without selected span attribute", func(td ptrace.Traces) {
			secondSpan(td).Attributes().Remove("password")
			secondSpan(td).Events().At(0).Attributes().PutInt("enc.other", 1)
		}},
		{"link reserved", func(td ptrace.Traces) {
			secondSpan(td).Links().At(0).Attributes().PutStr("enc.other", "occupied")
		}},
		{"non-string selected", func(td ptrace.Traces) {
			secondSpan(td).Attributes().PutInt("password", 7)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			td := twoSpanBatch()
			tc.change(td)
			before := traceBytes(t, td)
			next := &recordingConsumer{}
			p := testProcessor(t, next, "password")
			require.True(t, p.Capabilities().MutatesData)
			err := p.ConsumeTraces(t.Context(), td)
			require.Error(t, err)
			require.NotContains(t, err.Error(), "abc")
			require.NotContains(t, err.Error(), "second")
			require.Equal(t, before, traceBytes(t, td))
			require.Zero(t, next.calls)
		})
	}
}

func TestConsumeTracesReplacesOnlySelectedSpanAttributes(t *testing.T) {
	td := twoSpanBatch()
	first := td.ResourceSpans().At(0).ScopeSpans().At(0).Spans().At(0)
	first.Attributes().PutStr("Password", "case-sensitive")
	first.Attributes().PutStr("token", "abc")
	secondSpan(td).Attributes().PutStr("password", "")
	next := &recordingConsumer{}
	p := testProcessor(t, next, "password", "token")
	require.NoError(t, p.ConsumeTraces(t.Context(), td))
	require.Equal(t, 1, next.calls)
	require.True(t, p.Capabilities().MutatesData)

	for index, expected := range []string{fixtureABC, fixtureEmpty} {
		resource := next.traces.ResourceSpans().At(index)
		require.Equal(t, "resource-plain", getString(t, resource.Resource().Attributes(), "password"))
		require.Equal(t, "unchanged", getString(t, resource.Resource().Attributes(), "resource.other"))
		scope := resource.ScopeSpans().At(0)
		require.Equal(t, "scope-plain", getString(t, scope.Scope().Attributes(), "password"))
		span := scope.Spans().At(0)
		_, present := span.Attributes().Get("password")
		require.False(t, present)
		require.Equal(t, expected, getString(t, span.Attributes(), "enc.password"))
		require.Equal(t, "test-span", span.Name())
		require.Equal(t, int64(42), getInt(t, span.Attributes(), "span.other"))
		require.Equal(t, "event-plain", getString(t, span.Events().At(0).Attributes(), "password"))
		require.Equal(t, "link-plain", getString(t, span.Links().At(0).Attributes(), "password"))
		_, present = span.Attributes().Get("enc_eq.password")
		require.False(t, present)
	}
	require.Equal(t, fixtureTokenABC, getString(t, first.Attributes(), "enc.token"))
	require.Equal(t, "case-sensitive", getString(t, first.Attributes(), "Password"))
	_, present := first.Attributes().Get("token")
	require.False(t, present)
	_, present = secondSpan(td).Attributes().Get("enc.token")
	require.False(t, present)
}

func TestConsumeTracesUsesPolicyKeyForEachName(t *testing.T) {
	firstKey := fixtureKeyFile(t, fixtureKey)
	secondKey := fixtureKeyFile(t, fixtureOtherKey)
	cfg := &Config{Policies: []Policy{
		{SpanAttributes: []string{"password"}, KeyFile: firstKey, ValueScheme: valueScheme},
		{SpanAttributes: []string{"token"}, KeyFile: secondKey, ValueScheme: valueScheme},
	}}
	next := &recordingConsumer{}
	p, err := createTracesProcessor(t.Context(), processor.Settings{}, cfg, next)
	require.NoError(t, err)
	td := ptrace.NewTraces()
	span := td.ResourceSpans().AppendEmpty().ScopeSpans().AppendEmpty().Spans().AppendEmpty()
	span.Attributes().PutStr("password", "abc")
	span.Attributes().PutStr("token", "abc")
	require.NoError(t, p.ConsumeTraces(t.Context(), td))
	require.Equal(t, 1, next.calls)
	require.Equal(t, fixtureABC, getString(t, span.Attributes(), "enc.password"))
	second, err := newEncryptor(secondKey, valueScheme)
	require.NoError(t, err)
	require.NotEqual(t, "630dcd2966c4336691125448bbb25b4f", second.kid)
	expected, err := second.seal("enc.token", "abc")
	require.NoError(t, err)
	require.Equal(t, expected, getString(t, span.Attributes(), "enc.token"))
	require.Equal(t, 2, span.Attributes().Len())
}

func TestConsumeTracesSecondPolicyFailureLeavesBatchUnchanged(t *testing.T) {
	firstKey := fixtureKeyFile(t, fixtureKey)
	secondKey := fixtureKeyFile(t, fixtureOtherKey)
	cfg := &Config{Policies: []Policy{
		{SpanAttributes: []string{"password"}, KeyFile: firstKey, ValueScheme: valueScheme},
		{SpanAttributes: []string{"token"}, KeyFile: secondKey, ValueScheme: valueScheme},
	}}
	next := &recordingConsumer{}
	p, err := createTracesProcessor(t.Context(), processor.Settings{}, cfg, next)
	require.NoError(t, err)
	td := twoSpanBatch()
	td.ResourceSpans().At(0).ScopeSpans().At(0).Spans().At(0).Attributes().PutStr("token", "first-token")
	secondSpan(td).Attributes().PutInt("token", 7)
	before := traceBytes(t, td)
	require.Error(t, p.ConsumeTraces(t.Context(), td))
	require.Equal(t, before, traceBytes(t, td))
	require.Zero(t, next.calls)
}

func TestConsumeTracesEmptyStringSingleField(t *testing.T) {
	td := ptrace.NewTraces()
	span := td.ResourceSpans().AppendEmpty().ScopeSpans().AppendEmpty().Spans().AppendEmpty()
	span.Attributes().PutStr("password", "")
	next := &recordingConsumer{}
	require.NoError(t, testProcessor(t, next, "password").ConsumeTraces(t.Context(), td))
	require.Equal(t, 1, next.calls)
	require.Equal(t, 1, span.Attributes().Len())
	require.Equal(t, fixtureEmpty, getString(t, span.Attributes(), "enc.password"))
}

func TestConsumeTracesPropagatesDownstreamError(t *testing.T) {
	td := twoSpanBatch()
	want := errors.New("downstream unavailable")
	next := &recordingConsumer{err: want}
	err := testProcessor(t, next, "password").ConsumeTraces(t.Context(), td)
	require.ErrorIs(t, err, want)
	require.Equal(t, 1, next.calls)
	require.Equal(t, fixtureABC, getString(t, td.ResourceSpans().At(0).ScopeSpans().At(0).Spans().At(0).Attributes(), "enc.password"))
}

func getString(t *testing.T, attrs pcommon.Map, name string) string {
	t.Helper()
	value, ok := attrs.Get(name)
	require.True(t, ok, "missing attribute %s", name)
	require.Equal(t, pcommon.ValueTypeStr, value.Type())
	return value.Str()
}

func getInt(t *testing.T, attrs pcommon.Map, name string) int64 {
	t.Helper()
	value, ok := attrs.Get(name)
	require.True(t, ok, "missing attribute %s", name)
	require.Equal(t, pcommon.ValueTypeInt, value.Type())
	return value.Int()
}
