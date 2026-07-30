package ocsf

import "strings"

// OCSF severity_id values (schema 1.x).
const (
	SeverityUnknown       = 0
	SeverityInformational = 1
	SeverityLow           = 2
	SeverityMedium        = 3
	SeverityHigh          = 4
	SeverityCritical      = 5
	SeverityFatal         = 6
)

// SeverityName returns the canonical OCSF severity label for an id.
func SeverityName(id int) string {
	switch id {
	case SeverityInformational:
		return "Informational"
	case SeverityLow:
		return "Low"
	case SeverityMedium:
		return "Medium"
	case SeverityHigh:
		return "High"
	case SeverityCritical:
		return "Critical"
	case SeverityFatal:
		return "Fatal"
	default:
		return "Unknown"
	}
}

// ParseSeverity maps an OCSF/common severity label to severity_id.
func ParseSeverity(label string) (int, string) {
	switch strings.ToLower(strings.TrimSpace(label)) {
	case "informational", "info", "information":
		return SeverityInformational, "Informational"
	case "low":
		return SeverityLow, "Low"
	case "medium", "med":
		return SeverityMedium, "Medium"
	case "high":
		return SeverityHigh, "High"
	case "critical", "crit":
		return SeverityCritical, "Critical"
	case "fatal":
		return SeverityFatal, "Fatal"
	case "unknown":
		return SeverityUnknown, "Unknown"
	default:
		return 0, ""
	}
}

// EnsureSeverity fills severity_id/severity when missing.
// Classified telemetry (class_uid > 0) defaults to Informational — not Unknown —
// matching OCSF practice for routine endpoint activity.
func (e *Envelope) EnsureSeverity() {
	if e == nil {
		return
	}
	if e.SeverityID > 0 {
		if e.Severity == "" {
			e.Severity = SeverityName(e.SeverityID)
		}
		return
	}
	if id, name := ParseSeverity(e.Severity); id > 0 {
		e.SeverityID, e.Severity = id, name
		return
	}
	if e.ClassUID > 0 {
		e.SeverityID = SeverityInformational
		e.Severity = "Informational"
	}
}
