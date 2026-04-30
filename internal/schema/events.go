package schema

import "time"

const (
	SchemaVersionV1 = "v1"
)

type EventType string

const (
	EventProcess   EventType = "process"
	EventFile      EventType = "file"
	EventNetwork   EventType = "network"
	EventAuth      EventType = "auth"
	EventFork      EventType = "fork"
	EventRegistry  EventType = "registry"
	EventInjection EventType = "injection"
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
	SigningStatus string `json:"signing_status,omitempty"`
	TLSClientJA3  string `json:"tls_client_ja3,omitempty"`
	CloneFlags    uint64 `json:"clone_flags,omitempty"`
	UnshareFlags  uint64 `json:"unshare_flags,omitempty"`
	MadviseAdvice int32  `json:"madvise_advice,omitempty"`
	// ExecEnv holds environment entries joined with ASCII RS (0x1e) from ESF NOTIFY_EXEC / AUTH_EXEC.
	ExecEnv   string         `json:"exec_env,omitempty"`
	Tags      []string       `json:"tags,omitempty"`
	Severity  string         `json:"severity,omitempty"`
	Ancestors []AncestorInfo `json:"ancestors,omitempty"`
}

type FileEvent struct {
	BaseEvent
	Path      string `json:"path"`
	Operation string `json:"operation"`
	ActorPID  int    `json:"actor_pid"`
	// SubjectUID is the auditing subject UID when known (auditd / enriched JSON sources).
	SubjectUID    string `json:"subject_uid,omitempty"`
	Hash          string `json:"hash,omitempty"`
	WriteFD       int    `json:"write_fd,omitempty"`
	BytesWritten  uint64 `json:"bytes_written,omitempty"`
	OpenFlags     uint32 `json:"open_flags,omitempty"`
	ChmodMode     uint32 `json:"chmod_mode,omitempty"`
	FchmodatFlags uint32 `json:"fchmodat_flags,omitempty"`
	SUID          bool   `json:"suid,omitempty"`
	ImpHash       string `json:"imp_hash,omitempty"`
}

// ProcessInjectionEvent describes cross-process code injection indicators (e.g. ETW-TI).
type ProcessInjectionEvent struct {
	BaseEvent
	SourcePID   int    `json:"source_pid"`
	TargetPID   int    `json:"target_pid"`
	TargetImage string `json:"target_image,omitempty"`
	Technique   string `json:"technique,omitempty"`
}

// ForkEvent describes process creation via fork/clone (kernel or JSON pipeline).
type ForkEvent struct {
	BaseEvent
	ParentPID   int    `json:"parent_pid"`
	ChildPID    int    `json:"child_pid"`
	CloneFlags  uint64 `json:"clone_flags,omitempty"`
	IsThread    bool   `json:"is_thread,omitempty"`
	IsContainer bool   `json:"is_container,omitempty"`
}

// RegistryEvent describes a Windows registry operation or snapshot row.
type RegistryEvent struct {
	BaseEvent
	KeyPath   string `json:"key_path"`
	ValueName string `json:"value_name,omitempty"`
	Operation string `json:"operation"`
	OldData   string `json:"old_data,omitempty"`
	NewData   string `json:"new_data,omitempty"`
	ActorPID  int    `json:"actor_pid,omitempty"`
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
	JA3      string `json:"ja3,omitempty"`
	// Transport is a coarse label (tcp, udp, icmp) for SIEM join with Zeek conn logs.
	Transport string `json:"transport,omitempty"`
	// CommunityID is an optional RFC-style flow hash shared with Zeek when both endpoints compute it.
	CommunityID string `json:"community_id,omitempty"`
}

type AuthEvent struct {
	BaseEvent
	EventID        uint32   `json:"event_id,omitempty"`
	User           string   `json:"user"`
	Outcome        string   `json:"outcome"`
	AuthType       string   `json:"auth_type"`
	SourceIP       string   `json:"source_ip,omitempty"`
	SessionID      string   `json:"session_id,omitempty"`
	LogonType      string   `json:"logon_type,omitempty"`
	PrivilegeList  string   `json:"privilege_list,omitempty"`
	SubjectUser    string   `json:"subject_user,omitempty"`
	SubjectDomain  string   `json:"subject_domain,omitempty"`
	TargetUser     string   `json:"target_user,omitempty"`
	TargetDomain   string   `json:"target_domain,omitempty"`
	LogonProcess   string   `json:"logon_process,omitempty"`
	AuthPackage    string   `json:"auth_package,omitempty"`
	IpAddress      string   `json:"ip_address,omitempty"`
	IpPort         string   `json:"ip_port,omitempty"`
	Workstation    string   `json:"workstation,omitempty"`
	LogonGuid      string   `json:"logon_guid,omitempty"`
	PrivilegeListV []string `json:"privilege_list_v2,omitempty"`
	FailureReason  string   `json:"failure_reason,omitempty"`
	Status         string   `json:"status,omitempty"`
	SubStatus      string   `json:"sub_status,omitempty"`
	Success        bool     `json:"success"`
	Privileged     bool     `json:"privileged,omitempty"`
	SubjectLogonID string   `json:"subject_logon_id,omitempty"`
}

type TaskEvent struct {
	BaseEvent
	EventID     uint32 `json:"event_id,omitempty"`
	SubjectUser string `json:"subject_user,omitempty"`
	TaskName    string `json:"task_name,omitempty"`
	TaskContent string `json:"task_content,omitempty"`
	Operation   string `json:"operation,omitempty"`
}

type ServiceEvent struct {
	BaseEvent
	EventID     uint32 `json:"event_id,omitempty"`
	ServiceName string `json:"service_name,omitempty"`
	ImagePath   string `json:"image_path,omitempty"`
	ServiceType string `json:"service_type,omitempty"`
	StartType   string `json:"start_type,omitempty"`
	AccountName string `json:"account_name,omitempty"`
}

type CredentialAccessEvent struct {
	BaseEvent
	Technique     string `json:"technique,omitempty"`
	SourcePID     uint32 `json:"source_pid,omitempty"`
	SourceProcess string `json:"source_process,omitempty"`
	TargetPath    string `json:"target_path,omitempty"`
	AccessMask    uint32 `json:"access_mask,omitempty"`
	Severity      string `json:"severity,omitempty"`
}

type MemoryEvent struct {
	BaseEvent
	Operation     string `json:"operation,omitempty"`
	TargetPID     uint32 `json:"target_pid,omitempty"`
	TargetProcess string `json:"target_process,omitempty"`
	Address       uint64 `json:"address,omitempty"`
	Size          uint64 `json:"size,omitempty"`
	Protect       uint32 `json:"protect,omitempty"`
}

type ContainerEvent struct {
	BaseEvent
	Operation   string `json:"operation,omitempty"`
	PID         int    `json:"pid,omitempty"`
	ProcessName string `json:"process_name,omitempty"`
	Path        string `json:"path,omitempty"`
	Mode        uint32 `json:"mode,omitempty"`
}

type SecurityPolicyEvent struct {
	BaseEvent
	Operation string `json:"operation,omitempty"`
	PID       int    `json:"pid,omitempty"`
	Flags     uint64 `json:"flags,omitempty"`
}

type TamperEvent struct {
	BaseEvent
	Component string `json:"component,omitempty"`
	ProgramID uint32 `json:"program_id,omitempty"`
	Message   string `json:"message,omitempty"`
}

type AncestorInfo struct {
	PID       uint32 `json:"pid,omitempty"`
	Path      string `json:"path,omitempty"`
	SigningID string `json:"signing_id,omitempty"`
}

type PersistenceEvent struct {
	BaseEvent
	Technique      string `json:"technique,omitempty"`
	ExecutablePath string `json:"executable_path,omitempty"`
	ItemType       string `json:"item_type,omitempty"`
	IsLegacy       bool   `json:"is_legacy,omitempty"`
	IsManaged      bool   `json:"is_managed,omitempty"`
	UID            uint32 `json:"uid,omitempty"`
	PID            uint32 `json:"pid,omitempty"`
	ProcessPath    string `json:"process_path,omitempty"`
}

type PrivacyEvent struct {
	BaseEvent
	Operation        string `json:"operation,omitempty"`
	Service          string `json:"service,omitempty"`
	AuthValue        int    `json:"auth_value,omitempty"`
	AuthReason       string `json:"auth_reason,omitempty"`
	AccessingPID     uint32 `json:"accessing_pid,omitempty"`
	AccessingProcess string `json:"accessing_process,omitempty"`
}

type GatekeeperBypassEvent struct {
	BaseEvent
	FilePath      string `json:"file_path,omitempty"`
	PID           uint32 `json:"pid,omitempty"`
	ProcessPath   string `json:"process_path,omitempty"`
	SigningStatus string `json:"signing_status,omitempty"`
}

type DroppedEventsEvent struct {
	BaseEvent
	EventClass string `json:"event_class,omitempty"`
	GapSize    uint64 `json:"gap_size,omitempty"`
	LastSeq    uint64 `json:"last_seq,omitempty"`
	CurrentSeq uint64 `json:"current_seq,omitempty"`
}

type TIStatusEvent struct {
	BaseEvent
	Status string `json:"status,omitempty"`
	Reason string `json:"reason,omitempty"`
}

type FeatureStatusEvent struct {
	BaseEvent
	Features map[string]bool `json:"features,omitempty"`
	Degraded []string        `json:"degraded,omitempty"`
}
