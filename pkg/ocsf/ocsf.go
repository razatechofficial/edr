// Package ocsf provides OCSF 1.x event envelopes for detection and export.
// See https://schema.ocsf.io/ for the canonical schema.
package ocsf

const (
	SchemaVersion = "1.3.0"

	ClassSecurityFinding  = "security_finding"
	ClassUIDSecurityFinding = 2001

	ClassProcessActivity  = "process_activity"
	ClassUIDProcessActivity = 1007

	ClassFileActivity     = "file_activity"
	ClassUIDFileActivity  = 4001
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
	Unmapped     map[string]any `json:"unmapped,omitempty"`
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

type Process struct {
	Name     string `json:"name,omitempty"`
	Path     string `json:"path,omitempty"`
	CmdLine  string `json:"cmd_line,omitempty"`
	UID      string `json:"uid,omitempty"`
	PID      int    `json:"pid,omitempty"`
	ParentPID int   `json:"parent_process_uid,omitempty"`
}

type File struct {
	Name string `json:"name,omitempty"`
	Path string `json:"path,omitempty"`
	Type string `json:"type,omitempty"`
}
