package collector

import (
	"runtime"
	"time"

	"github.com/razatechofficial/edr/internal/schema"
)

// PostureFinding is a single posture probe anomaly suitable for compliance telemetry.
type PostureFinding struct {
	ProbeID string
	Title   string
	Detail  string
}

func postureFindingsToTelemetry(endpointID, hostname string, findings []PostureFinding) []Telemetry {
	if len(findings) == 0 {
		return nil
	}
	now := time.Now().UTC()
	out := make([]Telemetry, 0, len(findings))
	for _, f := range findings {
		ev := &schema.ComplianceFindingEvent{
			BaseEvent: schema.BaseEvent{
				SchemaVersion: schema.SchemaVersionV1,
				EventType:     schema.EventCompliance,
				EndpointID:    endpointID,
				Timestamp:     now,
				Hostname:      hostname,
				OS:            runtime.GOOS,
			},
			PolicyID:    "posture",
			PolicyName:  "Host posture probes",
			CheckID:     0,
			Title:       f.Title,
			Description: f.Detail,
			Result:      "failed",
		}
		out = append(out, Telemetry{Compliance: ev})
	}
	return out
}

func postureIntFromAny(v any) int {
	switch x := v.(type) {
	case int:
		return x
	case int64:
		return int(x)
	case float64:
		return int(x)
	case uint64:
		return int(x)
	default:
		return 0
	}
}

func postureBoolFromAny(v any) bool {
	switch x := v.(type) {
	case bool:
		return x
	default:
		return false
	}
}

func postureStringFromAny(v any) string {
	switch x := v.(type) {
	case string:
		return x
	default:
		return ""
	}
}
