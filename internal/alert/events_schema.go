package alert

import (
	"github.com/razatechofficial/edr/internal/schema"
	"github.com/razatechofficial/edr/pkg/events"
)

// EventsFromSchema converts a schema alert into the pipeline events.Alert type.
func EventsFromSchema(al schema.Alert) *events.Alert {
	return &events.Alert{
		ID:          al.AlertID,
		RuleID:      al.RuleID,
		RuleName:    al.Title,
		Title:       al.Title,
		Description: al.Description,
		Severity:    schemaSeverityToEvents(al.Severity),
		Timestamp:   al.Timestamp,
		FilePath:    al.FilePath,
		FileSHA256:  al.FileSHA256,
	}
}

func schemaSeverityToEvents(s schema.Severity) events.Severity {
	switch s {
	case schema.SeverityCritical:
		return events.SeverityCritical
	case schema.SeverityHigh:
		return events.SeverityHigh
	case schema.SeverityMedium:
		return events.SeverityMedium
	default:
		return events.SeverityLow
	}
}
