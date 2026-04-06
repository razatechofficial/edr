package schema

import "time"

type ResponseAction string

const (
	ResponseKillProcess ResponseAction = "kill_process"
	ResponseQuarantine  ResponseAction = "quarantine_file"
	ResponseHostIsolate ResponseAction = "host_isolate"
)

type ResponseCommand struct {
	SchemaVersion string         `json:"schema_version"`
	CommandID     string         `json:"command_id"`
	EndpointID    string         `json:"endpoint_id"`
	Action        ResponseAction `json:"action"`
	RequestedBy   string         `json:"requested_by"`
	Reason        string         `json:"reason"`
	ProcessPID    int            `json:"process_pid,omitempty"`
	ProcessName   string         `json:"process_name,omitempty"`
	FilePath      string         `json:"file_path,omitempty"`
	CreatedAt     time.Time      `json:"created_at"`
	ExpiresAt     time.Time      `json:"expires_at"`
	Nonce         string         `json:"nonce"`
	Signature     string         `json:"signature"`
}

type ResponseResult struct {
	SchemaVersion string         `json:"schema_version"`
	CommandID     string         `json:"command_id"`
	EndpointID    string         `json:"endpoint_id"`
	Action        ResponseAction `json:"action"`
	Success       bool           `json:"success"`
	Message       string         `json:"message"`
	Timestamp     time.Time      `json:"timestamp"`
}
