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
	ChildPID    int      `json:"child_pid,omitempty"`
	PPID        int      `json:"ppid"`
	ParentName  string   `json:"parent_name,omitempty"`
	ProcessName string   `json:"process_name"`
	ProcessPath string   `json:"process_path"`
	CommandLine string   `json:"command_line"`
	User        string   `json:"user"`
	Hashes      []string `json:"hashes,omitempty"`
	// Code signing metadata (e.g. macOS ESF exec enrichment).
	SigningTeamID string `json:"signing_team_id,omitempty"`
	ImageCDHash   string `json:"image_cdhash,omitempty"`
	SigningFlags  uint32 `json:"signing_flags,omitempty"`
	ImageSHA256   string `json:"image_sha256,omitempty"`
	TLSClientJA3  string `json:"tls_client_ja3,omitempty"`
	CloneFlags    uint64 `json:"clone_flags,omitempty"`
	UnshareFlags  uint64 `json:"unshare_flags,omitempty"`
	MadviseAdvice int32  `json:"madvise_advice,omitempty"`
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
