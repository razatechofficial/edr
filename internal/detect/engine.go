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
		if r.EventType != "" && r.EventType != "process" {
			continue
		}
		if !matchProcessRule(r, ev) {
			continue
		}
		out = append(out, schema.Alert{
			SchemaVersion: schema.SchemaVersionV1,
			AlertID:       uuid.NewString(),
			RuleID:        r.ID,
			EndpointID:    ev.EndpointID,
			Severity:      mapSeverity(r.Severity),
			Score:         ruleScore(r),
			Title:         r.Name,
			Description:   ruleDescription(r, "rule matched on process telemetry"),
			Timestamp:     time.Now().UTC(),
			ProcessPID:    ev.PID,
			ProcessName:   ev.ProcessName,
			ProcessPath:   ev.ProcessPath,
			CommandLine:   ev.CommandLine,
		})
	}
	return out
}

func (e *Engine) EvaluateFile(ev schema.FileEvent) []schema.Alert {
	var out []schema.Alert
	for _, r := range e.rules.Rules {
		if r.EventType != "file" {
			continue
		}
		if !matchFileRule(r, ev) {
			continue
		}
		out = append(out, schema.Alert{
			SchemaVersion: schema.SchemaVersionV1,
			AlertID:       uuid.NewString(),
			RuleID:        r.ID,
			EndpointID:    ev.EndpointID,
			Severity:      mapSeverity(r.Severity),
			Score:         ruleScore(r),
			Title:         r.Name,
			Description:   ruleDescription(r, "rule matched on file telemetry"),
			Timestamp:     time.Now().UTC(),
			FilePath:      ev.Path,
			FileOperation: ev.Operation,
			ProcessPID:    ev.ActorPID,
		})
	}
	return out
}

func (e *Engine) EvaluateNetwork(ev schema.NetworkEvent) []schema.Alert {
	var out []schema.Alert
	for _, r := range e.rules.Rules {
		if r.EventType != "network" {
			continue
		}
		if !matchNetworkRule(r, ev) {
			continue
		}
		out = append(out, schema.Alert{
			SchemaVersion: schema.SchemaVersionV1,
			AlertID:       uuid.NewString(),
			RuleID:        r.ID,
			EndpointID:    ev.EndpointID,
			Severity:      mapSeverity(r.Severity),
			Score:         ruleScore(r),
			Title:         r.Name,
			Description:   ruleDescription(r, "rule matched on network telemetry"),
			Timestamp:     time.Now().UTC(),
			ProcessPID:    ev.PID,
			Protocol:      ev.Protocol,
			DestIP:        ev.DestIP,
			DestPort:      ev.DestPt,
			Domain:        ev.Domain,
		})
	}
	return out
}

func (e *Engine) EvaluateAuth(ev schema.AuthEvent) []schema.Alert {
	var out []schema.Alert
	for _, r := range e.rules.Rules {
		if r.EventType != "auth" {
			continue
		}
		if !matchAuthRule(r, ev) {
			continue
		}
		out = append(out, schema.Alert{
			SchemaVersion: schema.SchemaVersionV1,
			AlertID:       uuid.NewString(),
			RuleID:        r.ID,
			EndpointID:    ev.EndpointID,
			Severity:      mapSeverity(r.Severity),
			Score:         ruleScore(r),
			Title:         r.Name,
			Description:   ruleDescription(r, "rule matched on auth telemetry"),
			Timestamp:     time.Now().UTC(),
			User:          ev.User,
			AuthType:      ev.AuthType,
			Outcome:       ev.Outcome,
			SourceIP:      ev.SourceIP,
		})
	}
	return out
}

// --- Process matching ---

func matchProcessRule(r rules.Rule, ev schema.ProcessEvent) bool {
	w := r.When
	if len(w.ParentIn) > 0 && !containsAnyFold(ev.ParentName, w.ParentIn) {
		return false
	}
	if len(w.ChildIn) > 0 && !containsAnyFold(ev.ProcessName, w.ChildIn) {
		return false
	}
	if len(w.ProcessPathContains) > 0 && !anySubstring(ev.ProcessPath, w.ProcessPathContains) {
		return false
	}
	if len(w.CommandLineContains) > 0 && !anySubstring(ev.CommandLine, w.CommandLineContains) {
		return false
	}
	if len(w.CommandLineAll) > 0 && !allSubstrings(ev.CommandLine, w.CommandLineAll) {
		return false
	}
	return true
}

// --- File matching ---

func matchFileRule(r rules.Rule, ev schema.FileEvent) bool {
	w := r.When
	if len(w.FilePathContains) > 0 && !anySubstring(ev.Path, w.FilePathContains) {
		return false
	}
	if len(w.FilePathNotContains) > 0 && anySubstring(ev.Path, w.FilePathNotContains) {
		return false
	}
	if len(w.OperationIn) > 0 && !containsAnyFold(ev.Operation, w.OperationIn) {
		return false
	}
	return true
}

// --- Network matching ---

func matchNetworkRule(r rules.Rule, ev schema.NetworkEvent) bool {
	w := r.When
	if len(w.DestIPContains) > 0 && !anySubstring(ev.DestIP, w.DestIPContains) {
		return false
	}
	if len(w.DestPortIn) > 0 && !intIn(ev.DestPt, w.DestPortIn) {
		return false
	}
	if len(w.ProtocolIn) > 0 && !containsAnyFold(ev.Protocol, w.ProtocolIn) {
		return false
	}
	if len(w.DomainContains) > 0 && !anySubstring(ev.Domain, w.DomainContains) {
		return false
	}
	return true
}

// --- Auth matching ---

func matchAuthRule(r rules.Rule, ev schema.AuthEvent) bool {
	w := r.When
	if len(w.SrcUserContains) > 0 && !anySubstring(ev.User, w.SrcUserContains) {
		return false
	}
	if len(w.OutcomeIn) > 0 && !containsAnyFold(ev.Outcome, w.OutcomeIn) {
		return false
	}
	if len(w.AuthTypeIn) > 0 && !containsAnyFold(ev.AuthType, w.AuthTypeIn) {
		return false
	}
	if len(w.SourceIPContains) > 0 && !anySubstring(ev.SourceIP, w.SourceIPContains) {
		return false
	}
	return true
}

// --- Helpers ---

func containsAnyFold(v string, options []string) bool {
	v = strings.ToLower(strings.TrimSpace(v))
	for _, s := range options {
		if strings.ToLower(strings.TrimSpace(s)) == v {
			return true
		}
	}
	return false
}

func anySubstring(v string, parts []string) bool {
	v = strings.ToLower(v)
	for _, p := range parts {
		if strings.Contains(v, strings.ToLower(p)) {
			return true
		}
	}
	return false
}

func allSubstrings(v string, parts []string) bool {
	v = strings.ToLower(v)
	for _, p := range parts {
		if !strings.Contains(v, strings.ToLower(p)) {
			return false
		}
	}
	return true
}

func intIn(v int, set []int) bool {
	for _, n := range set {
		if v == n {
			return true
		}
	}
	return false
}

func ruleScore(r rules.Rule) int {
	if r.Score > 0 {
		return r.Score
	}
	return scoreSeverity(r.Severity)
}

func ruleDescription(r rules.Rule, fallback string) string {
	if r.Description != "" {
		return r.Description
	}
	return fallback
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
