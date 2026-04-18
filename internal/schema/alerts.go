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

	// Process context
	ProcessPID  int    `json:"process_pid,omitempty"`
	ProcessName string `json:"process_name,omitempty"`
	ProcessPath string `json:"process_path,omitempty"`
	CommandLine string `json:"command_line,omitempty"`

	// File context
	FilePath      string `json:"file_path,omitempty"`
	FileSHA256    string `json:"file_sha256,omitempty"`
	FileOperation string `json:"file_operation,omitempty"`

	// Network context
	Protocol string `json:"protocol,omitempty"`
	DestIP   string `json:"dest_ip,omitempty"`
	DestPort int    `json:"dest_port,omitempty"`
	Domain   string `json:"domain,omitempty"`

	// Auth context
	User     string `json:"user,omitempty"`
	AuthType string `json:"auth_type,omitempty"`
	Outcome  string `json:"outcome,omitempty"`
	SourceIP string `json:"source_ip,omitempty"`
}

type AuditRecord struct {
	SchemaVersion string    `json:"schema_version"`
	RecordID      string    `json:"record_id"`
	Action        string    `json:"action"`
	Outcome       string    `json:"outcome"`
	Message       string    `json:"message"`
	Timestamp     time.Time `json:"timestamp"`
}
