// Package encryptedlogs seals configured Loki field values before forwarding entries.
package encryptedlogs

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"sync"
	"unicode/utf8"

	"github.com/grafana/alloy/internal/component"
	"github.com/grafana/alloy/internal/component/common/loki"
	"github.com/grafana/alloy/internal/component/common/lokiprotect"
	"github.com/grafana/alloy/internal/featuregate"
	"github.com/grafana/alloy/syntax"
	"github.com/prometheus/common/model"
)

func init() {
	component.Register(component.Registration{
		Name: "loki.encrypted_logs", Stability: featuregate.StabilityExperimental,
		Args: Arguments{}, Exports: Exports{},
		Build: func(opts component.Options, args component.Arguments) (component.Component, error) {
			return New(opts, args.(Arguments))
		},
	})
}

// Arguments configures exact field selections and downstream receivers.
// Protected pipelines must not configure downstream loki.write external_labels
// or downstream stages that add plaintext labels: they run after protection.
type Arguments struct {
	Policies  []lokiprotect.Policy `alloy:"policy,block"`
	ForwardTo []loki.LogsReceiver `alloy:"forward_to,attr"`
}

func (a *Arguments) Validate() error { return validatePolicies(a.Policies) }

var _ syntax.Validator = (*Arguments)(nil)

// Exports makes the log receiver available to upstream Loki components.
type Exports struct {
	Receiver loki.LogsReceiver `alloy:"receiver,attr"`
}

// Component preflights each entry in its entirety before sending it downstream.
type Component struct {
	receiver loki.LogsReceiver
	fanout   *loki.Fanout
	mut      sync.RWMutex
	protector *lokiprotect.Protector
	stopped  bool
}

var _ component.Component = (*Component)(nil)

func validatePolicies(policies []lokiprotect.Policy) error {
	if err := lokiprotect.ValidatePolicies(policies); err != nil {
		return err
	}
	seenNames := make(map[string]string)
	for _, policy := range policies {
		for _, field := range policy.Fields {
			_, name, _ := strings.Cut(field, ".")
			if previous, exists := seenNames[name]; exists && previous != field {
				return fmt.Errorf("encrypted_logs: ambiguous fields %q and %q", previous, field)
			}
			seenNames[name] = field
		}
	}
	return nil
}

// New validates selections and loads keys before exposing its receiver.
func New(opts component.Options, args Arguments) (*Component, error) {
	c := &Component{receiver: loki.NewLogsReceiver(loki.WithComponentID(opts.ID)), fanout: loki.NewFanout(args.ForwardTo)}
	if err := c.Update(args); err != nil {
		return nil, err
	}
	opts.OnStateChange(Exports{Receiver: c.receiver})
	return c, nil
}

func (c *Component) Update(args component.Arguments) error {
	newArgs := args.(Arguments)
	if err := validatePolicies(newArgs.Policies); err != nil {
		return err
	}
	protector, err := lokiprotect.New(newArgs.Policies)
	if err != nil {
		return err
	}
	c.mut.Lock()
	defer c.mut.Unlock()
	if c.stopped {
		return loki.ErrConsumerStopped
	}
	c.protector = protector
	c.fanout.UpdateChildren(newArgs.ForwardTo)
	return nil
}

func (c *Component) Run(ctx context.Context) error {
	defer func() {
		c.mut.Lock()
		c.stopped = true
		c.mut.Unlock()
	}()
	for {
		select {
		case <-ctx.Done():
			return nil
		case entry := <-c.receiver.Chan():
			// Hold the policy lock through Send: Update replaces the protector
			// and destinations together, never between protection and delivery.
			c.mut.RLock()
			if c.stopped {
				c.mut.RUnlock()
				continue
			}
			sealed, err := protectEntry(c.protector, entry)
			if err != nil {
				// Never log the entry or its failed value; drop the whole entry.
				c.mut.RUnlock()
				continue
			}
			err = c.fanout.Send(ctx, sealed)
			c.mut.RUnlock()
			if err != nil {
				return nil
			}
		}
	}
}

// fieldValue tracks the origin of each public or selected field. Cross-category
// reuse of a selected name is ambiguous, even when the values differ.
type fieldValue struct {
	path  string
	name  string
	value string
}

// Loki's logfmt extraction sanitizes keys by trimming whitespace, prefixing
// digit-leading names, and replacing non-identifier runes with '_'.
// Reject aliases rather than encrypting under a different associated-data name.
func normalizedFieldName(name string) string {
	name = strings.TrimSpace(name)
	if name != "" && name[0] >= '0' && name[0] <= '9' {
		name = "_" + name
	}
	return strings.Map(func(r rune) rune {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' ||
			r >= '0' && r <= '9' || r == '_' {
			return r
		}
		return '_'
	}, name)
}

func protectEntry(p *lokiprotect.Protector, entry loki.Entry) (loki.Entry, error) {
	if len(entry.Parsed) != 0 {
		return loki.Entry{}, fmt.Errorf("uninspected parsed fields")
	}
	fields := p.Fields()
	selected := make(map[string]string, len(fields))
	selectedNames := make(map[string]bool, len(fields))
	for _, path := range fields {
		_, name, _ := strings.Cut(path, ".")
		selectedNames[name] = true
	}
	values := make([]fieldValue, 0, len(entry.Labels)+len(entry.StructuredMetadata))
	for name, value := range entry.Labels {
		values = append(values, fieldValue{"label." + string(name), string(name), string(value)})
	}
	seenMetadata := make(map[string]bool, len(entry.StructuredMetadata))
	for _, label := range entry.StructuredMetadata {
		if seenMetadata[label.Name] {
			return loki.Entry{}, fmt.Errorf("duplicate metadata field")
		}
		seenMetadata[label.Name] = true
		values = append(values, fieldValue{"metadata." + label.Name, label.Name, label.Value})
	}
	parsed, err := parseLine(entry.Line)
	if err != nil {
		return loki.Entry{}, err
	}
	for _, item := range parsed {
		values = append(values, fieldValue{"line." + item.name, item.name, item.value})
	}
	seenNames := make(map[string]string, len(values))
	for _, field := range values {
		if normalized := normalizedFieldName(field.name); normalized != field.name && selectedNames[normalized] {
			return loki.Entry{}, fmt.Errorf("ambiguous normalized field name")
		}
		if selectedNames[field.name] {
			if previous, exists := seenNames[field.name]; exists && previous != field.path {
				return loki.Entry{}, fmt.Errorf("ambiguous field name")
			}
			seenNames[field.name] = field.path
		}
		if field.value == "" && p.Has(field.path) {
			return loki.Entry{}, fmt.Errorf("missing selected value")
		}
		if strings.HasPrefix(field.value, "lenc:") {
			return loki.Entry{}, fmt.Errorf("already encrypted literal")
		}
		if p.Has(field.path) {
			selected[field.path] = field.value
		} else if selectedNames[field.name] {
			return loki.Entry{}, fmt.Errorf("ambiguous field name")
		}
	}
	if len(selected) != len(fields) {
		return loki.Entry{}, fmt.Errorf("missing selected field")
	}
	// A field name is also emitted in plaintext, including a selected field's
	// original name. Reject secrets copied into any unselected value or name.
	for _, field := range values {
		for _, plaintext := range selected {
			if strings.Contains(field.name, plaintext) ||
				(!p.Has(field.path) && strings.Contains(field.value, plaintext)) {
				return loki.Entry{}, fmt.Errorf("unprotected copy of selected value")
			}
		}
	}
	// Seal before changing any part of the source entry. An error cannot produce
	// a partially protected entry, nor mutate the original shared label map.
	sealed := make(map[string]string, len(selected))
	for path, plaintext := range selected {
		value, err := p.Seal(path, plaintext)
		if err != nil {
			return loki.Entry{}, err
		}
		sealed[path] = value
	}
	if len(entry.Labels) != 0 {
		for name := range entry.Labels {
			if _, ok := sealed["label."+string(name)]; ok {
				entry.Labels = entry.Labels.Clone()
				break
			}
		}
		for name := range entry.Labels {
			if value, ok := sealed["label."+string(name)]; ok {
				entry.Labels[name] = model.LabelValue(value)
			}
		}
	}
	clonedMetadata := false
	for i, label := range entry.StructuredMetadata {
		if value, ok := sealed["metadata."+label.Name]; ok {
			if !clonedMetadata {
				entry.StructuredMetadata = slices.Clone(entry.StructuredMetadata)
				clonedMetadata = true
			}
			entry.StructuredMetadata[i].Value = value
		}
	}
	var rebuilt strings.Builder
	last := 0
	for _, item := range parsed {
		if value, ok := sealed["line."+item.name]; ok {
			rebuilt.WriteString(entry.Line[last:item.start])
			if item.quoted {
				rebuilt.WriteByte('"')
			}
			rebuilt.WriteString(value)
			if item.quoted {
				rebuilt.WriteByte('"')
			}
			last = item.end
		}
	}
	if last != 0 {
		rebuilt.WriteString(entry.Line[last:])
		entry.Line = rebuilt.String()
	}
	return entry, nil
}

// lineField retains source byte ranges so public fields and separators remain
// byte-for-byte unchanged when selected values are replaced.
type lineField struct {
	name, value string
	start, end int
	quoted bool
}

func parseLine(line string) ([]lineField, error) {
	if !utf8.ValidString(line) || strings.ContainsAny(line, "\r\n") {
		return nil, fmt.Errorf("invalid logfmt record")
	}
	var parsed []lineField
	seen := make(map[string]bool)
	for i := 0; i < len(line); {
		for i < len(line) && (line[i] == ' ' || line[i] == '\t') {
			i++
		}
		if i == len(line) {
			break
		}
		start := i
		for i < len(line) && line[i] != '=' && line[i] != ' ' && line[i] != '\t' {
			if line[i] == '"' || line[i] < ' ' {
				return nil, fmt.Errorf("invalid logfmt key")
			}
			i++
		}
		if i == start || i == len(line) || line[i] != '=' || seen[line[start:i]] {
			return nil, fmt.Errorf("invalid or duplicate logfmt key")
		}
		name := line[start:i]
		seen[name] = true
		i++
		item := lineField{name: name, start: i}
		if i < len(line) && line[i] == '"' {
			item.quoted = true
			start = i
			i++
			escaped := false
			for i < len(line) {
				if line[i] == '"' && !escaped {
					i++
					break
				}
				if line[i] == '\\' && !escaped {
					escaped = true
				} else {
					escaped = false
				}
				i++
			}
			if i > len(line) || line[i-1] != '"' || !json.Valid([]byte(line[start:i])) || json.Unmarshal([]byte(line[start:i]), &item.value) != nil {
				return nil, fmt.Errorf("invalid logfmt quoted value")
			}
		} else {
			start = i
			for i < len(line) && line[i] != ' ' && line[i] != '\t' {
				if line[i] == '=' || line[i] == '"' || line[i] < ' ' {
					return nil, fmt.Errorf("invalid logfmt value")
				}
				i++
			}
			item.value = line[start:i]
		}
		item.end = i
		if i < len(line) && line[i] != ' ' && line[i] != '\t' {
			return nil, fmt.Errorf("invalid logfmt separator")
		}
		parsed = append(parsed, item)
	}
	return parsed, nil
}
