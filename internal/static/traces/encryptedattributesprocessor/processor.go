package encryptedattributesprocessor

import (
	"context"
	"fmt"
	"strings"

	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/consumer"
	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/ptrace"
	otelprocessor "go.opentelemetry.io/collector/processor"
)

var _ otelprocessor.Traces = (*encryptedProcessor)(nil)

type encryptedProcessor struct {
	nextConsumer consumer.Traces
	selected     map[string]selectedAttribute // Immutable after construction.
}

type selectedAttribute struct {
	stored         string
	sidecar        string
	substringIndex bool
	encryptor      *encryptor
}

type attributeMutation struct {
	attributes pcommon.Map
	original   string
	stored     string
	value      string
	sidecar    string
	tokens     []string
}

func newProcessor(next consumer.Traces, cfg *Config, encryptors []*encryptor) *encryptedProcessor {
	selected := make(map[string]selectedAttribute)
	for i, policy := range cfg.Policies {
		for _, name := range policy.SpanAttributes {
			selected[name] = selectedAttribute{
				stored:         "enc." + name,
				sidecar:        "bi." + name,
				substringIndex: policy.SubstringIndex == substringIndex,
				encryptor:      encryptors[i],
			}
		}
	}
	return &encryptedProcessor{nextConsumer: next, selected: selected}
}

func (*encryptedProcessor) Start(context.Context, component.Host) error { return nil }

func (*encryptedProcessor) Shutdown(context.Context) error { return nil }

func (*encryptedProcessor) Capabilities() consumer.Capabilities {
	return consumer.Capabilities{MutatesData: true}
}

func (p *encryptedProcessor) ConsumeTraces(ctx context.Context, td ptrace.Traces) error {
	// Keep the stage local to this call. Nothing in td changes until every attribute
	// in the batch has passed preflight and every selected value has been sealed.
	var mutations []attributeMutation
	resourceSpans := td.ResourceSpans()
	for i := range resourceSpans.Len() {
		resource := resourceSpans.At(i)
		if err := p.preflight(resource.Resource().Attributes(), "resource", nil, &mutations); err != nil {
			return err
		}
		scopes := resource.ScopeSpans()
		for j := range scopes.Len() {
			scope := scopes.At(j)
			if err := p.preflight(scope.Scope().Attributes(), "scope", nil, &mutations); err != nil {
				return err
			}
			spans := scope.Spans()
			for k := range spans.Len() {
				span := spans.At(k)
				if err := p.preflight(span.Attributes(), "span", p.selected, &mutations); err != nil {
					return err
				}
				events := span.Events()
				for n := range events.Len() {
					if err := p.preflight(events.At(n).Attributes(), "event", nil, &mutations); err != nil {
						return err
					}
				}
				links := span.Links()
				for n := range links.Len() {
					if err := p.preflight(links.At(n).Attributes(), "link", nil, &mutations); err != nil {
						return err
					}
				}
			}
		}
	}

	for _, mutation := range mutations {
		mutation.attributes.Remove(mutation.original)
		mutation.attributes.PutStr(mutation.stored, mutation.value)
		if len(mutation.tokens) != 0 {
			sidecar := mutation.attributes.PutEmptySlice(mutation.sidecar)
			for _, token := range mutation.tokens {
				sidecar.AppendEmpty().SetStr(token)
			}
		}
	}
	return p.nextConsumer.ConsumeTraces(ctx, td)
}

func (p *encryptedProcessor) preflight(attributes pcommon.Map, scope string, selected map[string]selectedAttribute, mutations *[]attributeMutation) error {
	var err error
	attributes.Range(func(name string, value pcommon.Value) bool {
		if strings.HasPrefix(name, "enc.") || strings.HasPrefix(name, "bi.") {
			err = fmt.Errorf("reserved attribute name %q in %s attributes", name, scope)
			return false
		}
		attribute, ok := selected[name]
		if !ok {
			return true
		}
		if value.Type() != pcommon.ValueTypeStr {
			err = fmt.Errorf("selected span attribute %q must be a string", name)
			return false
		}
		var tokens []string
		if attribute.substringIndex {
			var indexErr error
			tokens, indexErr = attribute.encryptor.indexTokens(attribute.stored, value.Str())
			if indexErr != nil {
				err = fmt.Errorf("failed to index selected span attribute %q: %w", name, indexErr)
				return false
			}
		}
		sealed, sealErr := attribute.encryptor.seal(attribute.stored, value.Str())
		if sealErr != nil {
			// Encryption errors may contain implementation details; never include values.
			err = fmt.Errorf("failed to encrypt selected span attribute %q", name)
			return false
		}
		*mutations = append(*mutations, attributeMutation{
			attributes: attributes,
			original:   name,
			stored:     attribute.stored,
			value:      sealed,
			sidecar:    attribute.sidecar,
			tokens:     tokens,
		})
		return true
	})
	return err
}
