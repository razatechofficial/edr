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
	EventCompliance EventType = "compliance"
	EventComplianceScan EventType = "compliance_scan"
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
	TLSClientJA4  string `json:"tls_client_ja4,omitempty"`
	CloneFlags    uint64 `json:"clone_flags,omitempty"`
	UnshareFlags  uint64 `json:"unshare_flags,omitempty"`
	MadviseAdvice int32  `json:"madvise_advice,omitempty"`
	// ExecEnv holds environment entries joined with ASCII RS (0x1e) from ESF NOTIFY_EXEC / AUTH_EXEC.
	ExecEnv   string         `json:"exec_env,omitempty"`
	// ESFEventType is the raw Endpoint Security event type integer (macOS Sigma esf.event_type).
	ESFEventType int    `json:"esf_type,omitempty"`
	ESFOperation string `json:"esf_op,omitempty"`
	// TargetImage is the signal/get_task target process path on macOS ESF events.
	TargetImage  string `json:"target_image,omitempty"`
	SignalNumber int    `json:"signal_number,omitempty"`
	Tags      []string       `json:"tags,omitempty"`
	Severity  string         `json:"severity,omitempty"`
	Ancestors []AncestorInfo `json:"ancestors,omitempty"`

	// P2-6 enrichment fields.
	// IntegrityLevel reflects the Windows token integrity level (Low,
	// Medium, High, System). Empty on non-Windows.
	IntegrityLevel string `json:"integrity_level,omitempty"`
	// TokenElevationType is the Windows TOKEN_ELEVATION_TYPE
	// (1=Default, 2=Full, 3=Limited). Zero on non-Windows.
	TokenElevationType uint32 `json:"token_elevation_type,omitempty"`
	// LogonID ties a process create event back to the originating
	// Security log 4624 by Subject Logon ID.
	LogonID string `json:"logon_id,omitempty"`
	// CommandLineHash is SHA-256 hex of CommandLine (lower-case, no
	// truncation) so detection rules can match on a stable hash even
	// when raw CommandLine is truncated by ETW.
	CommandLineHash string `json:"command_line_hash,omitempty"`
}

type FileEvent struct {
	BaseEvent
	Path      string `json:"path"`
	Operation string `json:"operation"`
	ActorPID  int    `json:"actor_pid"`
	// Who-data parity (audit / eBPF / ESF).
	ActorPPID    int    `json:"actor_ppid,omitempty"`
	AuditUID     string `json:"audit_uid,omitempty"`
	EffectiveUID string `json:"effective_uid,omitempty"`
	ActorComm    string `json:"actor_comm,omitempty"`
	ActorExe     string `json:"actor_exe,omitempty"`
	Syscall      string `json:"syscall,omitempty"`
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
	Tags          []string `json:"tags,omitempty"`
	// FIMDiffUnified is a base64-encoded unified diff vs prior capped snapshot (optional FIM diff).
	FIMDiffUnified string `json:"fim_diff_unified,omitempty"`
	// ESFEventType is the raw Endpoint Security event type integer (macOS Sigma esf.event_type).
	ESFEventType int    `json:"esf_type,omitempty"`
	ESFOperation string `json:"esf_op,omitempty"`
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
	// SNI is observed from TLS client hello (userland/kernel stub), distinct from DNS-derived Domain.
	SNI      string `json:"sni,omitempty"`
	JA3      string `json:"ja3,omitempty"`
	// JA4 is a compact TLS ClientHello fingerprint (local computation when raw hello bytes exist).
	JA4 string `json:"ja4,omitempty"`
	// JA3S is an MD5 fingerprint of the observed TLS ServerHello when bytes are available locally.
	JA3S string `json:"ja3s,omitempty"`
	JA4S string `json:"ja4s,omitempty"`
	// Transport is a coarse label (tcp, udp, icmp) for SIEM join with Zeek conn logs.
	Transport string `json:"transport,omitempty"`
	// CommunityID is an optional RFC-style flow hash shared with Zeek when both endpoints compute it.
	CommunityID string `json:"community_id,omitempty"`

	// P2-6 connection-level metrics. BytesIn / BytesOut are the
	// kernel-counted byte totals on connection close (TCP) or
	// per-packet totals (UDP). DurationMs is the lifetime of the flow
	// in milliseconds, computed from connect to close.
	BytesIn    uint64 `json:"bytes_in,omitempty"`
	BytesOut   uint64 `json:"bytes_out,omitempty"`
	DurationMs uint64 `json:"duration_ms,omitempty"`
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
	// Message holds the raw log line (macOS unified log / auth stream).
	Message   string `json:"message,omitempty"`
	Subsystem string `json:"subsystem,omitempty"`
	Category  string `json:"category,omitempty"`
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

// ComplianceFindingEvent is a Security Configuration Assessment (SCA) check result.
type ComplianceFindingEvent struct {
	BaseEvent
	PolicyID    string              `json:"policy_id"`
	PolicyName  string              `json:"policy_name"`
	CheckID     int                 `json:"check_id"`
	Title       string              `json:"title"`
	Description string              `json:"description,omitempty"`
	Remediation string              `json:"remediation,omitempty"`
	Result      string              `json:"result"` // passed|failed|not_applicable|error
	Error       string              `json:"error,omitempty"`
	Compliance  map[string][]string `json:"compliance,omitempty"`
	MITRE       map[string][]string `json:"mitre,omitempty"`
	OCSF        map[string]any      `json:"ocsf,omitempty"`
}

// ComplianceScanSummaryEvent summarizes one full SCA scan run across applicable policies.
type ComplianceScanSummaryEvent struct {
	BaseEvent
	Passed              int   `json:"passed"`
	Failed              int   `json:"failed"`
	Errors              int   `json:"errors"`
	Skipped             int   `json:"skipped"`
	PoliciesTotal       int   `json:"policies_total"`
	PoliciesApplicable  int   `json:"policies_applicable"`
	DurationMs          int64 `json:"duration_ms"`
	OCSF                map[string]any `json:"ocsf,omitempty"`
}

// PrivilegeEvent is emitted when a process invokes a privilege-change
// syscall (setuid/setgid family). Distinct from SignalEvent so SIEM
// queries can scope on identity-elevation activity directly. The Linux
// eBPF emitter populates Operation and NewUID/NewGID; ETW/ESF paths can
// reuse the same shape for cross-platform parity.
type PrivilegeEvent struct {
	BaseEvent
	PID        uint32 `json:"pid"`
	PPID       uint32 `json:"ppid,omitempty"`
	Comm       string `json:"comm,omitempty"`
	Operation  string `json:"operation,omitempty"`
	SyscallNr  uint32 `json:"syscall_nr,omitempty"`
	NewUID     uint32 `json:"new_uid,omitempty"`
	NewGID     uint32 `json:"new_gid,omitempty"`
	EffectiveID uint32 `json:"effective_id,omitempty"`
	SavedID    uint32 `json:"saved_id,omitempty"`
	CallerUID  uint32 `json:"caller_uid,omitempty"`
}
