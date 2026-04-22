// Package playbooks provides pre-built automated response sequences for
// common threat scenarios. Each playbook implements the response.Playbook
// interface and can be executed atomically with rollback via the
// [response.ActionEngine].
package playbooks

import (
	"context"

	"github.com/razatechofficial/edr/internal/response"
	"github.com/razatechofficial/edr/pkg/events"
)

// Step is an alias for response.PlaybookStep for convenience within playbook
// implementations.
type Step = response.PlaybookStep

// Playbook extends response.Playbook with a self-contained Execute method
// that knows how to drive the engine through its steps.
type Playbook interface {
	response.Playbook
	Execute(ctx context.Context, engine *response.ActionEngine, alert *events.Alert) ([]*response.StepResult, error)
}

// BasePlaybook provides default implementations for the Playbook interface.
// Concrete playbooks embed this and override Steps() with their specific
// action sequence.
type BasePlaybook struct {
	PlaybookName  string
	PlaybookDesc  string
	PlaybookSteps []Step
}

// Name returns the playbook's human-readable name.
func (b *BasePlaybook) Name() string { return b.PlaybookName }

// Description returns a brief summary of what the playbook does.
func (b *BasePlaybook) Description() string { return b.PlaybookDesc }

// Steps returns the ordered list of playbook steps.
func (b *BasePlaybook) Steps() []response.PlaybookStep { return b.PlaybookSteps }

// Execute drives the response engine through every step, delegating rollback
// semantics to the engine's ExecutePlaybook method.
func (b *BasePlaybook) Execute(ctx context.Context, engine *response.ActionEngine, alert *events.Alert) ([]*response.StepResult, error) {
	return engine.ExecutePlaybook(ctx, b, alert)
}

// ---------------------------------------------------------------------------
// Alert extraction helpers used by playbook Params functions.
// ---------------------------------------------------------------------------

// ExtractPID attempts to pull a process ID from the alert's RawEvent.
func ExtractPID(alert *events.Alert) int {
	return extractIntField(alert, "pid")
}

// ExtractFilePath attempts to pull a file path from the alert's RawEvent.
func ExtractFilePath(alert *events.Alert) string {
	return extractStringField(alert, "path")
}

// ExtractProcessName attempts to pull a process name from the alert's RawEvent.
func ExtractProcessName(alert *events.Alert) string {
	return extractStringField(alert, "process_name")
}

// ExtractDestIP attempts to pull a destination IP from the alert's RawEvent.
func ExtractDestIP(alert *events.Alert) string {
	return extractStringField(alert, "dest_ip")
}

// ExtractSourceIP attempts to pull a source IP from the alert's RawEvent.
func ExtractSourceIP(alert *events.Alert) string {
	return extractStringField(alert, "source_ip")
}

// ExtractHash extracts a file hash from the alert's RawEvent or Tags.
func ExtractHash(alert *events.Alert) string {
	if h := extractStringField(alert, "hash"); h != "" {
		return h
	}
	for _, tag := range alert.Tags {
		if len(tag) == 64 { // SHA-256 hex
			return tag
		}
	}
	return ""
}

func extractIntField(alert *events.Alert, key string) int {
	if alert.RawEvent == nil {
		return 0
	}
	m, ok := alert.RawEvent.(map[string]interface{})
	if !ok {
		return 0
	}
	v, ok := m[key]
	if !ok {
		return 0
	}
	switch n := v.(type) {
	case int:
		return n
	case int64:
		return int(n)
	case float64:
		return int(n)
	}
	return 0
}

func extractStringField(alert *events.Alert, key string) string {
	if alert.RawEvent == nil {
		return ""
	}
	m, ok := alert.RawEvent.(map[string]interface{})
	if !ok {
		return ""
	}
	s, _ := m[key].(string)
	return s
}
