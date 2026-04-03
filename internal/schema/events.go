package schema

import "time"

const (
	SchemaVersionV1 = "v1"
)

type EventType string

const (
	EventProcess EventType = "process"
	EventFile    EventType = "file"
	EventNetwork EventType = "network"
	EventAuth    EventType = "auth"
)

type BaseEvent struct {
	SchemaVersion string    `json:"schema_version"`
	EventType     EventType `json:"event_type"`
	EndpointID    string    `json:"endpoint_id"`
	Timestamp     time.Time `json:"timestamp"`
	Hostname      string    `json:"hostname"`
	OS            string    `json:"os"`
}

type ProcessEvent struct {
	BaseEvent
	PID         int      `json:"pid"`
	PPID        int      `json:"ppid"`
	ProcessName string   `json:"process_name"`
	ProcessPath string   `json:"process_path"`
	CommandLine string   `json:"command_line"`
	User        string   `json:"user"`
	Hashes      []string `json:"hashes,omitempty"`
}

type FileEvent struct {
	BaseEvent
	Path      string `json:"path"`
	Operation string `json:"operation"`
	ActorPID  int    `json:"actor_pid"`
	Hash      string `json:"hash,omitempty"`
}

type NetworkEvent struct {
	BaseEvent
	PID      int    `json:"pid"`
	Protocol string `json:"protocol"`
	SourceIP string `json:"source_ip"`
	SourcePt int    `json:"source_port"`
	DestIP   string `json:"dest_ip"`
	DestPt   int    `json:"dest_port"`
	Domain   string `json:"domain,omitempty"`
}

type AuthEvent struct {
	BaseEvent
	User      string `json:"user"`
	Outcome   string `json:"outcome"`
	AuthType  string `json:"auth_type"`
	SourceIP  string `json:"source_ip,omitempty"`
	SessionID string `json:"session_id,omitempty"`
}
