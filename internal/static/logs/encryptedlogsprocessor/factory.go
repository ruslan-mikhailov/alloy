// Package encryptedlogsprocessor seals selected OTel log fields before Loki promotion.
//
// A policy field label.NAME selects the resource attribute NAME (the future Loki
// label), line.NAME selects a NAME=value pair in a string logfmt body, and
// metadata.NAME selects a log record attribute NAME (the future structured
// metadata). All configured fields must occur in every applicable record.
// The body must be a single strict key=value logfmt record, even without
// selected line fields, so decoded copies and name aliases can be rejected.
// Scope attributes and other carriers of a selected field name are unsupported.
// A selected value repeated in any unselected attribute or body value is
// rejected rather than allowed to escape in plaintext. Put this processor
// before Loki promotion.
package encryptedlogsprocessor

import (
	"context"
	"fmt"
	"strings"

	"github.com/grafana/alloy/internal/component/common/lokiprotect"
	"github.com/prometheus/otlptranslator"
	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/consumer"
	"go.opentelemetry.io/collector/processor"
)

const TypeStr = "encrypted_logs"

type Config struct {
	Policies []lokiprotect.Policy `mapstructure:"policies"`
}

func (cfg *Config) Validate() error {
	if cfg == nil {
		return fmt.Errorf("encrypted_logs: missing configuration")
	}
	if err := lokiprotect.ValidatePolicies(cfg.Policies); err != nil {
		return err
	}
	// A name selected in two carriers creates an ambiguous copy of the same
	// field: reject it before any logs are accepted.
	seen := make(map[string]bool)
	for _, policy := range cfg.Policies {
		for _, field := range policy.Fields {
			name := field[strings.IndexByte(field, '.')+1:]
			category := field[:strings.IndexByte(field, '.')]
			if category == "label" || category == "metadata" {
				promoted, err := (&otlptranslator.LabelNamer{}).Build(name)
				if err != nil || promoted != name {
					return fmt.Errorf("encrypted_logs: selected OTLP attribute %q changes name during Loki promotion", field)
				}
			}
			if seen[name] {
				return fmt.Errorf("encrypted_logs: field name %q selected in multiple carriers", name)
			}
			seen[name] = true
		}
	}
	return nil
}

func NewFactory() processor.Factory {
	return processor.NewFactory(
		component.MustNewType(TypeStr),
		func() component.Config { return &Config{} },
		processor.WithLogs(createLogsProcessor, component.StabilityLevelAlpha),
	)
}

func createLogsProcessor(_ context.Context, _ processor.Settings, cfg component.Config, next consumer.Logs) (processor.Logs, error) {
	config, ok := cfg.(*Config)
	if !ok {
		return nil, fmt.Errorf("encrypted_logs: invalid configuration type")
	}
	if err := config.Validate(); err != nil {
		return nil, err
	}
	protector, err := lokiprotect.New(config.Policies)
	if err != nil {
		return nil, err
	}
	p := &encryptedProcessor{
		next: next, protector: protector,
		labels: make(map[string]string), lines: make(map[string]string), metadata: make(map[string]string),
		selected: make(map[string]bool),
	}
	for _, field := range protector.Fields() {
		category, name, _ := strings.Cut(field, ".")
		p.selected[name] = true
		switch category {
		case "label":
			p.labels[name] = field
		case "line":
			p.lines[name] = field
		case "metadata":
			p.metadata[name] = field
		}
	}
	return p, nil
}
