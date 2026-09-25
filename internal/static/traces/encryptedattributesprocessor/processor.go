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
	encryptor    *encryptor
	selected     map[string]string // Original name to stored name; immutable after construction.
}

type attributeMutation struct {
	attributes pcommon.Map
	original   string
	stored     string
	value      string
}

func newProcessor(next consumer.Traces, cfg *Config, enc *encryptor) (*encryptedProcessor, error) {
	selected := make(map[string]string, len(cfg.SpanAttributes))
	for _, name := range cfg.SpanAttributes {
		selected[name] = "enc." + name
	}
	return &encryptedProcessor{nextConsumer: next, encryptor: enc, selected: selected}, nil
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
	}
	return p.nextConsumer.ConsumeTraces(ctx, td)
}

func (p *encryptedProcessor) preflight(attributes pcommon.Map, scope string, selected map[string]string, mutations *[]attributeMutation) error {
	var err error
	attributes.Range(func(name string, value pcommon.Value) bool {
		if strings.HasPrefix(name, "enc.") {
			err = fmt.Errorf("reserved attribute name %q in %s attributes", name, scope)
			return false
		}
		stored, ok := selected[name]
		if !ok {
			return true
		}
		if value.Type() != pcommon.ValueTypeStr {
			err = fmt.Errorf("selected span attribute %q must be a string", name)
			return false
		}
		sealed, sealErr := p.encryptor.seal(stored, value.Str())
		if sealErr != nil {
			// Encryption errors may contain implementation details; never include values.
			err = fmt.Errorf("failed to encrypt selected span attribute %q", name)
			return false
		}
		*mutations = append(*mutations, attributeMutation{
			attributes: attributes,
			original:   name,
			stored:     stored,
			value:      sealed,
		})
		return true
	})
	return err
}
