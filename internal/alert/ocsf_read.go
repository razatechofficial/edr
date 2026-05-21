package alert

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/razatechofficial/edr/internal/schema"
	"github.com/razatechofficial/edr/pkg/ocsf"
)

// ParseAlertLine decodes one JSONL alert row exported as OCSF or legacy flat schema.
func ParseAlertLine(line []byte) (schema.Alert, error) {
	line = []byte(strings.TrimSpace(string(line)))
	if len(line) == 0 {
		return schema.Alert{}, fmt.Errorf("alert: empty line")
	}
	var raw map[string]any
	if err := json.Unmarshal(line, &raw); err != nil {
		return schema.Alert{}, err
	}
	if isLegacyAlertJSON(raw) {
		var al schema.Alert
		if err := json.Unmarshal(line, &al); err != nil {
			return schema.Alert{}, err
		}
		return al, nil
	}
	return alertFromOCSFMap(raw)
}

func isLegacyAlertJSON(raw map[string]any) bool {
	if _, ok := raw["alert_id"]; ok {
		return true
	}
	if _, ok := raw["rule_id"]; ok {
		return true
	}
	if _, ok := raw["schema_version"]; ok {
		return true
	}
	return false
}

func alertFromOCSFMap(raw map[string]any) (schema.Alert, error) {
	al := schema.Alert{OCSF: raw}
	if uid, ok := intFromAny(raw["class_uid"]); ok && uid != ocsf.ClassUIDDetectionFinding {
		return al, fmt.Errorf("alert: unexpected class_uid %d", uid)
	}
	if f, ok := raw["finding"].(map[string]any); ok {
		if v := stringFromAny(f["title"]); v != "" {
			al.Title = v
		}
		if v := stringFromAny(f["desc"]); v != "" {
			al.Description = v
		}
		if v := stringFromAny(f["uid"]); v != "" {
			al.AlertID = v
		}
		if types, ok := f["types"].([]any); ok {
			if ruleID := ruleIDFromFindingTypes(types); ruleID != "" {
				al.RuleID = ruleID
			}
		}
	}
	if unmapped, ok := raw["unmapped"].(map[string]any); ok {
		if v := stringFromAny(unmapped["alert_id"]); v != "" {
			al.AlertID = v
		}
		if v := stringFromAny(unmapped["rule_id"]); v != "" {
			al.RuleID = v
		}
		if v := stringFromAny(unmapped["endpoint_id"]); v != "" {
			al.EndpointID = v
		}
		if v, ok := intFromAny(unmapped["score"]); ok {
			al.Score = v
		}
		if v := stringFromAny(unmapped["file_sha256"]); v != "" {
			al.FileSHA256 = v
		}
		if v := stringFromAny(unmapped["file_operation"]); v != "" {
			al.FileOperation = v
		}
		if v := stringFromAny(unmapped["protocol"]); v != "" {
			al.Protocol = v
		}
		if v := stringFromAny(unmapped["url"]); v != "" {
			al.URL = v
		}
		if v := stringFromAny(unmapped["auth_type"]); v != "" {
			al.AuthType = v
		}
		if v := stringFromAny(unmapped["auth_outcome"]); v != "" {
			al.Outcome = v
		}
	}
	if v, ok := intFromAny(raw["severity_id"]); ok {
		al.Severity = severityFromID(v)
	}
	if v := stringFromAny(raw["severity"]); v != "" && al.Severity == "" {
		al.Severity = schema.Severity(strings.ToLower(v))
	}
	if ms, ok := intFromAny(raw["time"]); ok && ms > 0 {
		al.Timestamp = time.UnixMilli(int64(ms)).UTC()
	}
	if proc, ok := raw["process"].(map[string]any); ok {
		if v, ok := intFromAny(proc["pid"]); ok {
			al.ProcessPID = v
		}
		if v := stringFromAny(proc["cmd_line"]); v != "" {
			al.CommandLine = v
		}
		if file, ok := proc["file"].(map[string]any); ok {
			if v := stringFromAny(file["name"]); v != "" {
				al.ProcessName = v
			}
			if v := stringFromAny(file["path"]); v != "" {
				al.ProcessPath = v
			}
		}
		if user, ok := proc["user"].(map[string]any); ok {
			if v := stringFromAny(user["name"]); v != "" {
				al.User = v
			}
		}
	}
	if file, ok := raw["file"].(map[string]any); ok {
		if v := stringFromAny(file["path"]); v != "" {
			al.FilePath = v
		}
	}
	if dst, ok := raw["dst_endpoint"].(map[string]any); ok {
		if v := stringFromAny(dst["ip"]); v != "" {
			al.DestIP = v
		}
		if v, ok := intFromAny(dst["port"]); ok {
			al.DestPort = v
		}
	}
	if src, ok := raw["src_endpoint"].(map[string]any); ok {
		if v := stringFromAny(src["ip"]); v != "" {
			al.SourceIP = v
		}
	}
	if q, ok := raw["query"].(map[string]any); ok {
		if v := stringFromAny(q["hostname"]); v != "" {
			al.Domain = v
		}
	}
	return al, nil
}

func ruleIDFromFindingTypes(types []any) string {
	for _, item := range types {
		s := strings.TrimSpace(stringFromAny(item))
		if s == "" || s == "Detection" || s == "EDR" {
			continue
		}
		return s
	}
	return ""
}

func severityFromID(id int) schema.Severity {
	switch id {
	case 5:
		return schema.SeverityCritical
	case 4:
		return schema.SeverityHigh
	case 3:
		return schema.SeverityMedium
	case 2:
		return schema.SeverityLow
	default:
		return schema.SeverityInfo
	}
}

func stringFromAny(v any) string {
	if v == nil {
		return ""
	}
	switch x := v.(type) {
	case string:
		return strings.TrimSpace(x)
	default:
		return strings.TrimSpace(fmt.Sprint(x))
	}
}

func intFromAny(v any) (int, bool) {
	if v == nil {
		return 0, false
	}
	switch x := v.(type) {
	case int:
		return x, true
	case int32:
		return int(x), true
	case int64:
		return int(x), true
	case float64:
		return int(x), true
	case float32:
		return int(x), true
	case json.Number:
		n, err := x.Int64()
		if err != nil {
			return 0, false
		}
		return int(n), true
	default:
		return 0, false
	}
}
