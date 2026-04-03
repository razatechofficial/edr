package schema

import "time"

type Severity string

const (
	SeverityInfo     Severity = "info"
	SeverityLow      Severity = "low"
	SeverityMedium   Severity = "medium"
	SeverityHigh     Severity = "high"
	SeverityCritical Severity = "critical"
)

type Alert struct {
	SchemaVersion string    `json:"schema_version"`
	AlertID       string    `json:"alert_id"`
	RuleID        string    `json:"rule_id"`
	EndpointID    string    `json:"endpoint_id"`
	Severity      Severity  `json:"severity"`
	Score         int       `json:"score"`
	Title         string    `json:"title"`
	Description   string    `json:"description"`
	Timestamp     time.Time `json:"timestamp"`
	ProcessPID    int       `json:"process_pid,omitempty"`
	ProcessName   string    `json:"process_name,omitempty"`
	ProcessPath   string    `json:"process_path,omitempty"`
	CommandLine   string    `json:"command_line,omitempty"`
}

type AuditRecord struct {
	SchemaVersion string    `json:"schema_version"`
	RecordID      string    `json:"record_id"`
	Action        string    `json:"action"`
	Outcome       string    `json:"outcome"`
	Message       string    `json:"message"`
	Timestamp     time.Time `json:"timestamp"`
}
