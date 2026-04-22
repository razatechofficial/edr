package detection

import (
	"time"

	"github.com/razatechofficial/edr/pkg/events"
)

// FromAlert converts a pipeline alert to a [Detection] for the response layer and other consumers.
func FromAlert(a *events.Alert) Detection {
	return alertToDetection(a)
}

func alertToDetection(a *events.Alert) Detection {
	d := Detection{
		ID:          a.ID,
		Timestamp:   a.Timestamp,
		RuleID:      a.RuleID,
		RuleName:    a.RuleName,
		Severity:    alertSeverityToP(a.Severity),
		Event:       EventPayloadFromInterface(a.RawEvent),
		Tags:        append([]string(nil), a.Tags...),
		Description: a.Description,
		Source:      sourceFromRule(a.RuleID),
	}
	if d.ID == "" {
		d.ID = a.RuleID + "-" + time.Now().UTC().Format(time.RFC3339Nano)
	}
	if len(a.MITRE) > 0 {
		d.TechniqueID = a.MITRE[0].TechniqueID
		d.TacticName = a.MITRE[0].TacticName
	}
	return d
}

func alertSeverityToP(s events.Severity) Severity {
	switch s {
	case events.SeverityCritical:
		return P0
	case events.SeverityHigh:
		return P1
	case events.SeverityMedium:
		return P2
	default:
		return P3
	}
}

func sourceFromRule(ruleID string) DetectionSource {
	switch {
	case len(ruleID) >= 5 && ruleID[:5] == "yara-":
		return SourceYARA
	case len(ruleID) >= 3 && ruleID[:3] == "ml-":
		return SourceML
	case len(ruleID) >= 10 && ruleID[:10] == "behavioral":
		return SourceBehavioral
	case len(ruleID) >= 6 && ruleID[:6] == "dedup-":
		return SourceDedup
	default:
		return SourceSigma
	}
}

func detectionToAlert(d Detection) *events.Alert {
	return &events.Alert{
		ID:          d.ID,
		RuleID:      d.RuleID,
		RuleName:    d.RuleName,
		Severity:    pToAlertSeverity(d.Severity),
		Title:       d.RuleName,
		Description: d.Description,
		Timestamp:   d.Timestamp,
		Tags:        append([]string(nil), d.Tags...),
		RawEvent:    rawEventFromPayload(d.Event),
		MITRE: []events.MITREAttack{{
			TechniqueID: d.TechniqueID,
			TacticName:  d.TacticName,
		}},
	}
}

func pToAlertSeverity(s Severity) events.Severity {
	switch s {
	case P0:
		return events.SeverityCritical
	case P1:
		return events.SeverityHigh
	case P2:
		return events.SeverityMedium
	default:
		return events.SeverityLow
	}
}
