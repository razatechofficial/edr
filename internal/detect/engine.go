package detect

import (
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/razatechofficial/edr/internal/rules"
	"github.com/razatechofficial/edr/internal/schema"
)

type Engine struct {
	rules rules.RuleSet
}

func NewEngine(rs rules.RuleSet) *Engine {
	return &Engine{rules: rs}
}

func (e *Engine) EvaluateProcess(ev schema.ProcessEvent) []schema.Alert {
	var out []schema.Alert
	for _, r := range e.rules.Rules {
		if !matchRule(r, ev) {
			continue
		}
		out = append(out, schema.Alert{
			SchemaVersion: schema.SchemaVersionV1,
			AlertID:       uuid.NewString(),
			RuleID:        r.ID,
			EndpointID:    ev.EndpointID,
			Severity:      mapSeverity(r.Severity),
			Score:         scoreSeverity(r.Severity),
			Title:         r.Name,
			Description:   "rule matched on process telemetry",
			Timestamp:     time.Now().UTC(),
			ProcessPID:    ev.PID,
			ProcessName:   ev.ProcessName,
			ProcessPath:   ev.ProcessPath,
			CommandLine:   ev.CommandLine,
		})
	}
	return out
}

func matchRule(r rules.Rule, ev schema.ProcessEvent) bool {
	if len(r.When.ParentIn) > 0 && !containsAnyFold(ev.ParentName, r.When.ParentIn) {
		return false
	}
	if len(r.When.ChildIn) > 0 && !containsAnyFold(ev.ProcessName, r.When.ChildIn) {
		return false
	}
	if len(r.When.ProcessPathContains) > 0 && !containsPath(ev.ProcessPath, r.When.ProcessPathContains) {
		return false
	}
	return true
}

func containsAnyFold(v string, options []string) bool {
	v = strings.ToLower(strings.TrimSpace(v))
	for _, s := range options {
		if strings.ToLower(strings.TrimSpace(s)) == v {
			return true
		}
	}
	return false
}

func containsPath(v string, parts []string) bool {
	v = strings.ToLower(v)
	for _, p := range parts {
		if strings.Contains(v, strings.ToLower(p)) {
			return true
		}
	}
	return false
}

func mapSeverity(v string) schema.Severity {
	switch strings.ToLower(v) {
	case "critical":
		return schema.SeverityCritical
	case "high":
		return schema.SeverityHigh
	case "medium":
		return schema.SeverityMedium
	case "low":
		return schema.SeverityLow
	default:
		return schema.SeverityInfo
	}
}

func scoreSeverity(v string) int {
	switch strings.ToLower(v) {
	case "critical":
		return 100
	case "high":
		return 80
	case "medium":
		return 55
	case "low":
		return 30
	default:
		return 10
	}
}
