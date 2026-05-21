package ocsf

import (
	"strings"
	"time"

	"github.com/google/uuid"
)

// AlertInput carries detection alert context for OCSF Detection Finding mapping.
type AlertInput struct {
	AlertID     string
	RuleID      string
	EndpointID  string
	Title       string
	Description string
	Severity    string
	Score       int
	Timestamp   time.Time

	ProcessPID  int
	ProcessName string
	ProcessPath string
	CommandLine string

	FilePath      string
	FileSHA256    string
	FileOperation string

	Protocol string
	DestIP   string
	DestPort int
	Domain   string
	SourceIP string
	URL      string

	User     string
	AuthType string
	Outcome  string
}

// FromDetectionAlert maps an agent detection alert to OCSF Detection Finding (class 2004).
func FromDetectionAlert(in AlertInput, product Product) Envelope {
	ts := in.Timestamp
	if ts.IsZero() {
		ts = time.Now().UTC()
	}
	sevID, sev := alertSeverity(in.Severity, in.Score)
	types := []string{"Detection", "EDR"}
	if in.RuleID != "" {
		types = append(types, in.RuleID)
	}
	env := Envelope{
		ClassUID:     ClassUIDDetectionFinding,
		ClassName:    ClassDetectionFinding,
		CategoryUID:  2,
		CategoryName: "Findings",
		ActivityID:   1,
		ActivityName: "Create",
		SeverityID:   sevID,
		Severity:     sev,
		Time:         ts.UnixMilli(),
		Metadata: Metadata{
			Version:     SchemaVersion,
			Product:     product,
			LogName:     "detection",
			LogProvider: "alert",
		},
		Finding: &Finding{
			UID:   firstNonEmptyStr(in.AlertID, uuid.NewString()),
			Title: in.Title,
			Desc:  in.Description,
			Types: types,
		},
		Unmapped: map[string]any{
			"alert_id":  in.AlertID,
			"rule_id":   in.RuleID,
			"endpoint_id": in.EndpointID,
			"score":     in.Score,
		},
	}
	if proc := processFromInput(ProcessInput{
		PID:         in.ProcessPID,
		ProcessName: in.ProcessName,
		ProcessPath: in.ProcessPath,
		CommandLine: in.CommandLine,
		User:        in.User,
	}); proc != nil {
		env.Process = proc
	}
	if path := strings.TrimSpace(in.FilePath); path != "" {
		env.File = &File{
			Name: filepathBase(path),
			Path: path,
			Type: "Regular File",
		}
	}
	if in.FileSHA256 != "" {
		if env.Unmapped == nil {
			env.Unmapped = map[string]any{}
		}
		env.Unmapped["file_sha256"] = in.FileSHA256
	}
	if in.FileOperation != "" {
		if env.Unmapped == nil {
			env.Unmapped = map[string]any{}
		}
		env.Unmapped["file_operation"] = in.FileOperation
	}
	if in.DestIP != "" || in.DestPort != 0 {
		env.DstEndpoint = &Endpoint{IP: in.DestIP, Port: in.DestPort}
	}
	if in.SourceIP != "" {
		env.SrcEndpoint = &Endpoint{IP: in.SourceIP}
	}
	if in.Domain != "" {
		env.Query = &DNSQuery{Hostname: in.Domain}
		if env.Unmapped == nil {
			env.Unmapped = map[string]any{}
		}
		env.Unmapped["domain"] = in.Domain
	}
	if in.Protocol != "" || in.URL != "" {
		if env.Unmapped == nil {
			env.Unmapped = map[string]any{}
		}
		env.Unmapped["protocol"] = in.Protocol
		env.Unmapped["url"] = in.URL
	}
	if in.AuthType != "" || in.Outcome != "" {
		if env.Unmapped == nil {
			env.Unmapped = map[string]any{}
		}
		env.Unmapped["auth_type"] = in.AuthType
		env.Unmapped["auth_outcome"] = in.Outcome
	}
	return env
}

func alertSeverity(severity string, score int) (int, string) {
	switch strings.ToLower(strings.TrimSpace(severity)) {
	case "critical":
		return 5, "Critical"
	case "high":
		return 4, "High"
	case "medium":
		return 3, "Medium"
	case "low":
		return 2, "Low"
	case "info":
		return 1, "Informational"
	}
	switch {
	case score >= 90:
		return 5, "Critical"
	case score >= 75:
		return 4, "High"
	case score >= 55:
		return 3, "Medium"
	case score >= 35:
		return 2, "Low"
	default:
		return 1, "Informational"
	}
}

func filepathBase(path string) string {
	if i := strings.LastIndexAny(path, `/\`); i >= 0 && i+1 < len(path) {
		return path[i+1:]
	}
	return path
}

func firstNonEmptyStr(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}
