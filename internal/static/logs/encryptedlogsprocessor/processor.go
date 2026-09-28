package encryptedlogsprocessor

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"unicode/utf8"

	"github.com/grafana/alloy/internal/component/common/lokiprotect"
	"github.com/prometheus/otlptranslator"
	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/consumer"
	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/plog"
	"go.opentelemetry.io/collector/processor"
)

var _ processor.Logs = (*encryptedProcessor)(nil)

type encryptedProcessor struct {
	next      consumer.Logs
	protector *lokiprotect.Protector
	labels    map[string]string
	lines     map[string]string
	metadata  map[string]string
	selected  map[string]bool
}

type mutation struct {
	attributes pcommon.Map
	body       pcommon.Value
	name       string
	value      string
}

func (*encryptedProcessor) Start(context.Context, component.Host) error { return nil }
func (*encryptedProcessor) Shutdown(context.Context) error             { return nil }
func (*encryptedProcessor) Capabilities() consumer.Capabilities {
	return consumer.Capabilities{MutatesData: true}
}

// ConsumeLogs stages every replacement and validates all plaintext copies before
// changing the input or invoking the next consumer. Errors never include values.
func (p *encryptedProcessor) ConsumeLogs(ctx context.Context, logs plog.Logs) error {
	var changes []mutation
	var plain, unselected []string
	resources := logs.ResourceLogs()
	for i := range resources.Len() {
		resource := resources.At(i)
		if err := p.inspectAttributes(resource.Resource().Attributes(), p.labels, "resource", &changes, &plain, &unselected); err != nil {
			return err
		}
		scopes := resource.ScopeLogs()
		for j := range scopes.Len() {
			scope := scopes.At(j)
			if err := p.inspectAttributes(scope.Scope().Attributes(), nil, "scope", &changes, &plain, &unselected); err != nil {
				return err
			}
			unselected = append(unselected, scope.Scope().Name(), scope.Scope().Version(), scope.SchemaUrl())
			if err := p.rejectGenerated("scope_name", scope.Scope().Name() != ""); err != nil {
				return err
			}
			if err := p.rejectGenerated("scope_version", scope.Scope().Version() != ""); err != nil {
				return err
			}
			if err := p.rejectGenerated("scope_dropped_attributes_count", scope.Scope().DroppedAttributesCount() != 0); err != nil {
				return err
			}
			records := scope.LogRecords()
			for k := range records.Len() {
				record := records.At(k)
				if err := p.inspectAttributes(record.Attributes(), p.metadata, "record", &changes, &plain, &unselected); err != nil {
					return err
				}
				unselected = append(unselected, record.SeverityText(), record.EventName())
				for _, generated := range []struct {
					name    string
					present bool
				}{
					{"event_name", record.EventName() != ""},
					{"severity_text", record.SeverityText() != ""},
					{"severity_number", record.SeverityNumber() != plog.SeverityNumberUnspecified},
					{"observed_timestamp", record.Timestamp() != 0 && record.ObservedTimestamp() != 0},
					{"dropped_attributes_count", record.DroppedAttributesCount() != 0},
					{"flags", record.Flags() != 0},
					{"trace_id", !record.TraceID().IsEmpty()},
					{"span_id", !record.SpanID().IsEmpty()},
				} {
					if err := p.rejectGenerated(generated.name, generated.present); err != nil {
						return err
					}
				}
				if record.Body().Type() != pcommon.ValueTypeStr {
					return fmt.Errorf("encrypted_logs: log body must be a string")
				}
				body := record.Body().Str()
				sealed, values, originals, err := p.sealLine(body)
				if err != nil {
					return err
				}
				plain = append(plain, originals...)
				unselected = append(unselected, values...)
				if len(p.lines) != 0 {
					changes = append(changes, mutation{body: record.Body(), value: sealed})
				}
			}
		}
		unselected = append(unselected, resource.SchemaUrl())
	}
	for _, secret := range plain {
		if secret == "" {
			continue
		}
		for name := range p.selected {
			if strings.Contains(name, secret) {
				return fmt.Errorf("encrypted_logs: selected plaintext also occurs in a field name")
			}
		}
		for _, value := range unselected {
			if strings.Contains(value, secret) {
				return fmt.Errorf("encrypted_logs: selected plaintext also occurs in an unselected field")
			}
		}
	}
	for _, change := range changes {
		if change.name == "" {
			change.body.SetStr(change.value)
		} else {
			change.attributes.PutStr(change.name, change.value)
		}
	}
	return p.next.ConsumeLogs(ctx, logs)
}

// rejectGenerated prevents Loki's built-in OTLP metadata from shadowing a
// selected attribute with the same eventual name.
func (p *encryptedProcessor) rejectGenerated(name string, present bool) error {
	if present && p.selected[name] {
		return fmt.Errorf("encrypted_logs: selected field %q collides with generated OTLP metadata", name)
	}
	return nil
}

func (p *encryptedProcessor) inspectAttributes(attributes pcommon.Map, selected map[string]string, carrier string, changes *[]mutation, plain, unselected *[]string) error {
	seen := make(map[string]bool, attributes.Len())
	found := make(map[string]bool, len(selected))
	var inspectErr error
	attributes.Range(func(name string, value pcommon.Value) bool {
		if seen[name] {
			inspectErr = fmt.Errorf("encrypted_logs: duplicate %s attribute %q", carrier, name)
			return false
		}
		seen[name] = true
		normalized, err := (&otlptranslator.LabelNamer{}).Build(name)
		if err != nil {
			inspectErr = fmt.Errorf("encrypted_logs: invalid %s attribute name", carrier)
			return false
		}
		if name != normalized && p.selected[normalized] {
			inspectErr = fmt.Errorf("encrypted_logs: %s attribute aliases selected field %q", carrier, normalized)
			return false
		}
		field, wanted := selected[name]
		if p.selected[name] && !wanted {
			inspectErr = fmt.Errorf("encrypted_logs: selected field %q also occurs in %s attributes", name, carrier)
			return false
		}
		// Nested values can contain uninspectable copies of protected data.
		if value.Type() != pcommon.ValueTypeStr {
			inspectErr = fmt.Errorf("encrypted_logs: unsupported non-string %s attribute", carrier)
			return false
		}
		text := value.Str()
		if !wanted {
			*unselected = append(*unselected, name, text)
			return true
		}
		sealed, err := p.protector.Seal(field, text)
		if err != nil {
			inspectErr = fmt.Errorf("encrypted_logs: invalid selected %s attribute %q", carrier, name)
			return false
		}
		found[name] = true
		*plain = append(*plain, text)
		*changes = append(*changes, mutation{attributes: attributes, name: name, value: sealed})
		return true
	})
	if inspectErr != nil {
		return inspectErr
	}
	for name := range selected {
		if !found[name] {
			return fmt.Errorf("encrypted_logs: missing selected %s attribute %q", carrier, name)
		}
	}
	return nil
}

// sealLine accepts one strict logfmt record. It replaces only selected value
// spans, leaving every other byte (including quoting and spacing) untouched.
func (p *encryptedProcessor) sealLine(body string) (string, []string, []string, error) {
	if !utf8.ValidString(body) || strings.ContainsAny(body, "\r\n") {
		return "", nil, nil, fmt.Errorf("encrypted_logs: malformed logfmt body")
	}
	var output strings.Builder
	seen := make(map[string]bool)
	var unselected, plain []string
	last := 0
	for pos := 0; pos < len(body); {
		if body[pos] == ' ' || body[pos] == '\t' {
			pos++
			continue
		}
		keyStart := pos
		for pos < len(body) && body[pos] != '=' && body[pos] != ' ' && body[pos] != '\t' {
			if body[pos] <= ' ' || body[pos] == '"' || body[pos] == '\\' {
				return "", nil, nil, fmt.Errorf("encrypted_logs: malformed logfmt key")
			}
			pos++
		}
		if pos == keyStart || pos == len(body) || body[pos] != '=' {
			return "", nil, nil, fmt.Errorf("encrypted_logs: logfmt requires key=value pairs")
		}
		key := body[keyStart:pos]
		// Loki's logfmt parser trims keys and replaces every non-ASCII
		// identifier rune with '_'. Compare its eventual name as well.
		normalized := strings.Map(func(r rune) rune {
			if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '_' {
				return r
			}
			return '_'
		}, strings.TrimSpace(key))
		if normalized != key && p.selected[normalized] {
			return "", nil, nil, fmt.Errorf("encrypted_logs: logfmt key aliases selected field %q", normalized)
		}
		if seen[key] {
			return "", nil, nil, fmt.Errorf("encrypted_logs: duplicate logfmt key")
		}
		seen[key] = true
		pos++
		valueStart := pos
		var value string
		if pos < len(body) && body[pos] == '"' {
			pos++
			closed := false
			for pos < len(body) {
				if body[pos] == '\\' {
					pos += 2
					continue
				}
				if body[pos] == '"' {
					pos++
					closed = true
					break
				}
				pos++
			}
			if !closed || (pos < len(body) && body[pos] != ' ' && body[pos] != '\t') {
				return "", nil, nil, fmt.Errorf("encrypted_logs: malformed quoted logfmt value")
			}
			if err := json.Unmarshal([]byte(body[valueStart:pos]), &value); err != nil {
				return "", nil, nil, fmt.Errorf("encrypted_logs: malformed quoted logfmt value")
			}
		} else {
			for pos < len(body) && body[pos] != ' ' && body[pos] != '\t' {
				if body[pos] <= ' ' || body[pos] == '=' || body[pos] == '"' {
					return "", nil, nil, fmt.Errorf("encrypted_logs: malformed logfmt value")
				}
				pos++
			}
			value = body[valueStart:pos]
		}
		field, wanted := p.lines[key]
		if p.selected[key] && !wanted {
			return "", nil, nil, fmt.Errorf("encrypted_logs: selected field %q also occurs in logfmt body", key)
		}
		if !wanted {
			unselected = append(unselected, key, value)
			continue
		}
		sealed, err := p.protector.Seal(field, value)
		if err != nil {
			return "", nil, nil, fmt.Errorf("encrypted_logs: invalid selected line field %q", key)
		}
		plain = append(plain, value)
		output.WriteString(body[last:valueStart])
		output.WriteString(sealed)
		last = pos
	}
	for name := range p.lines {
		if !seen[name] {
			return "", nil, nil, fmt.Errorf("encrypted_logs: missing selected line field %q", name)
		}
	}
	output.WriteString(body[last:])
	return output.String(), unselected, plain, nil
}
