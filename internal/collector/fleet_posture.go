package collector

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/razatechofficial/edr/internal/config"
)

// FleetPostureLabels summarizes monitoring_health.json + config into flat
// string labels for XDR ingest heartbeats (enrollment DeriveHealth).
func FleetPostureLabels(cfg config.Config) map[string]string {
	out := map[string]string{}
	tier := strings.TrimSpace(cfg.Monitoring.ChecklistTier)
	if tier == "" {
		tier = strings.TrimSpace(cfg.Monitoring.Mode)
	}
	if tier != "" {
		out["checklist_tier"] = strings.ToLower(tier)
	}
	mode := strings.TrimSpace(cfg.Monitoring.Mode)
	if mode != "" {
		out["monitoring_mode"] = strings.ToLower(mode)
	}

	path := filepath.Join(cfg.Agent.DataDir, "monitoring_health.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		// No snapshot yet — still report tier; sensor_data unknown until snapshot exists.
		return out
	}
	var doc struct {
		UpdatedAt string           `json:"updated_at"`
		Sources   []map[string]any `json:"sources"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return out
	}

	var (
		kernelStatus string
		rfmReason    string
		healthyN     int
		degradedN    int
		badN         int
		latestEvent  int64
	)
	for _, s := range doc.Sources {
		name, _ := s["name"].(string)
		status, _ := s["status"].(string)
		status = strings.ToLower(strings.TrimSpace(status))
		switch status {
		case "healthy":
			healthyN++
		case "degraded":
			degradedN++
		case "unavailable", "absent":
			badN++
		}
		if name == "kernel" {
			kernelStatus = status
			if notes, _ := s["notes"].(string); notes != "" && (status == "degraded" || status == "absent" || status == "unavailable") {
				rfmReason = truncateReason(notes)
			}
			if tamper, ok := s["tamper"].(map[string]any); ok {
				if dr := firstStringSlice(tamper["degraded_reason"]); dr != "" {
					rfmReason = truncateReason(dr)
				}
			}
		}
		if ts, ok := asInt64(s["last_event_unix"]); ok && ts > latestEvent {
			latestEvent = ts
		}
	}
	if kernelStatus != "" {
		out["kernel_status"] = kernelStatus
	}
	if rfmReason != "" {
		out["rfm_reason"] = rfmReason
	}

	switch {
	case len(doc.Sources) == 0:
		out["sensor_data"] = "heartbeat_only"
	case degradedN > 0 && badN == 0 && healthyN > 0:
		out["sensor_data"] = "partial"
	case badN > 0 && healthyN == 0:
		out["sensor_data"] = "heartbeat_only"
	case healthyN > 0 && degradedN == 0 && badN == 0:
		out["sensor_data"] = "full"
	case healthyN > 0:
		out["sensor_data"] = "partial"
	default:
		out["sensor_data"] = "partial"
	}

	if latestEvent > 0 {
		out["source_last_event_unix"] = strconv.FormatInt(latestEvent, 10)
		// Local mute hint for fleet: collectors quiet for >5m.
		if time.Since(time.Unix(latestEvent, 0)) > 5*time.Minute && out["sensor_data"] == "full" {
			out["sensor_data"] = "heartbeat_only"
		}
	}
	out["comms_status"] = "ok"
	return out
}

func asInt64(v any) (int64, bool) {
	switch t := v.(type) {
	case float64:
		return int64(t), true
	case int64:
		return t, true
	case int:
		return int64(t), true
	case json.Number:
		n, err := t.Int64()
		return n, err == nil
	default:
		return 0, false
	}
}

func firstStringSlice(v any) string {
	switch t := v.(type) {
	case []string:
		if len(t) > 0 {
			return t[0]
		}
	case []any:
		for _, x := range t {
			if s, ok := x.(string); ok && s != "" {
				return s
			}
		}
	case string:
		return t
	}
	return ""
}

func truncateReason(s string) string {
	s = strings.TrimSpace(s)
	if len(s) > 120 {
		return s[:117] + "..."
	}
	return s
}
