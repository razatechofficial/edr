// Package ocsf provides OCSF 1.x event envelopes for detection and export.
// See https://schema.ocsf.io/ for the canonical schema.
package ocsf

const (
	SchemaVersion = "1.3.0"

	ClassSecurityFinding  = "security_finding"
	ClassUIDSecurityFinding = 2001

	ClassDetectionFinding    = "detection_finding"
	ClassUIDDetectionFinding = 2004

	ClassProcessActivity  = "process_activity"
	ClassUIDProcessActivity = 1007

	ClassFileActivity     = "file_activity"
	ClassUIDFileActivity  = 4001

	ClassNetworkActivity    = "network_activity"
	ClassUIDNetworkActivity = 4003

	ClassAuthentication    = "authentication"
	ClassUIDAuthentication = 3002

	ClassRegistryKeyActivity    = "registry_key_activity"
	ClassUIDRegistryKeyActivity = 201001

	ClassDNSActivity    = "dns_activity"
	ClassUIDDNSActivity = 4004

	ClassScheduledJobActivity    = "scheduled_job_activity"
	ClassUIDScheduledJobActivity = 1006

	ClassWindowsServiceActivity    = "windows_service_activity"
	ClassUIDWindowsServiceActivity = 201004
)

// Envelope is the top-level OCSF event wrapper.
type Envelope struct {
	ClassUID     int            `json:"class_uid"`
	ClassName    string         `json:"class_name"`
	CategoryUID  int            `json:"category_uid,omitempty"`
	CategoryName string         `json:"category_name,omitempty"`
	ActivityID   int            `json:"activity_id,omitempty"`
	ActivityName string         `json:"activity_name,omitempty"`
	SeverityID   int            `json:"severity_id,omitempty"`
	Severity     string         `json:"severity,omitempty"`
	Time         int64          `json:"time"`
	Metadata     Metadata       `json:"metadata"`
	Finding      *Finding       `json:"finding,omitempty"`
	Process      *Process       `json:"process,omitempty"`
	File         *File          `json:"file,omitempty"`
	RegKey       *RegKey        `json:"reg_key,omitempty"`
	Query        *DNSQuery      `json:"query,omitempty"`
	Job          *ScheduledJob  `json:"job,omitempty"`
	SrcEndpoint  *Endpoint      `json:"src_endpoint,omitempty"`
	DstEndpoint  *Endpoint      `json:"dst_endpoint,omitempty"`
	User         *UserRecord    `json:"user,omitempty"`
	Status       string         `json:"status,omitempty"`
	StatusID     int            `json:"status_id,omitempty"`
	Unmapped     map[string]any `json:"unmapped,omitempty"`
}

type Endpoint struct {
	IP   string `json:"ip,omitempty"`
	Port int    `json:"port,omitempty"`
}

type UserRecord struct {
	Name      string `json:"name,omitempty"`
	Domain    string `json:"domain,omitempty"`
	Type      string `json:"type,omitempty"`
	TypeID    int    `json:"type_id,omitempty"`
	UID       string `json:"uid,omitempty"`
}

type Metadata struct {
	Version   string `json:"version"`
	Product   Product `json:"product"`
	Profiles  []string `json:"profiles,omitempty"`
	LogName   string `json:"log_name,omitempty"`
	LogProvider string `json:"log_provider,omitempty"`
}

type Product struct {
	Name    string `json:"name"`
	Vendor  string `json:"vendor_name"`
	Version string `json:"version,omitempty"`
}

type Finding struct {
	UID         string         `json:"uid,omitempty"`
	Title       string         `json:"title,omitempty"`
	Desc        string         `json:"desc,omitempty"`
	Types       []string       `json:"types,omitempty"`
	Remediation string         `json:"remediation,omitempty"`
	Compliance  map[string]any `json:"compliance,omitempty"`
}

type ProcessParent struct {
	PID int `json:"pid,omitempty"`
}

type ProcessFile struct {
	Name string `json:"name,omitempty"`
	Path string `json:"path,omitempty"`
}

type Process struct {
	File          *ProcessFile   `json:"file,omitempty"`
	CmdLine       string         `json:"cmd_line,omitempty"`
	User          *UserRecord    `json:"user,omitempty"`
	PID           int            `json:"pid,omitempty"`
	ParentProcess *ProcessParent `json:"parent_process,omitempty"`
}

type DNSQuery struct {
	Hostname string `json:"hostname,omitempty"`
}

type ScheduledJob struct {
	Name string `json:"name,omitempty"`
	Cmd  string `json:"cmd_line,omitempty"`
}

type File struct {
	Name string `json:"name,omitempty"`
	Path string `json:"path,omitempty"`
	Type string `json:"type,omitempty"`
}

type RegKey struct {
	Path string `json:"path,omitempty"`
}
