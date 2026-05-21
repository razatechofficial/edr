package ocsf

import (
	"path/filepath"
	"strings"
	"time"

	"github.com/google/uuid"
)

// ProcessInput is a neutral process snapshot for OCSF mapping.
type ProcessInput struct {
	EndpointID  string
	Hostname    string
	OS          string
	Timestamp   time.Time
	PID         int
	PPID        int
	ProcessName string
	ProcessPath string
	CommandLine string
	User        string
}

// FileInput is a neutral file event snapshot for OCSF mapping.
type FileInput struct {
	EndpointID string
	Timestamp  time.Time
	Path       string
	Operation  string
	ActorPID   int
}

// DefaultProduct identifies events emitted by the EDR agent.
func DefaultProduct(version string) Product {
	return Product{
		Name:    "edr-agent",
		Vendor:  "razatechofficial",
		Version: version,
	}
}

// FromProcess maps process telemetry to an OCSF Process Activity envelope.
func FromProcess(in ProcessInput, product Product) Envelope {
	ts := in.Timestamp
	if ts.IsZero() {
		ts = time.Now().UTC()
	}
	return Envelope{
		ClassUID:     ClassUIDProcessActivity,
		ClassName:    ClassProcessActivity,
		CategoryUID:  1,
		CategoryName: "System Activity",
		ActivityID:   1,
		ActivityName: "Launch",
		Time:         ts.UnixMilli(),
		Metadata: Metadata{
			Version: SchemaVersion,
			Product: product,
		},
		Process: &Process{
			Name:      in.ProcessName,
			Path:      in.ProcessPath,
			CmdLine:   in.CommandLine,
			UID:       in.User,
			PID:       in.PID,
			ParentPID: in.PPID,
		},
		Unmapped: map[string]any{
			"endpoint_id": in.EndpointID,
			"hostname":    in.Hostname,
			"os":          in.OS,
		},
	}
}

// FromFile maps file telemetry to an OCSF File Activity envelope.
func FromFile(in FileInput, product Product) Envelope {
	ts := in.Timestamp
	if ts.IsZero() {
		ts = time.Now().UTC()
	}
	return Envelope{
		ClassUID:     ClassUIDFileActivity,
		ClassName:    ClassFileActivity,
		CategoryUID:  4,
		CategoryName: "System Activity",
		ActivityID:   1,
		ActivityName: in.Operation,
		Time:         ts.UnixMilli(),
		Metadata: Metadata{
			Version: SchemaVersion,
			Product: product,
		},
		File: &File{
			Name: filepath.Base(in.Path),
			Path: in.Path,
			Type: "Regular File",
		},
		Unmapped: map[string]any{
			"endpoint_id": in.EndpointID,
			"actor_pid":   in.ActorPID,
			"operation":   in.Operation,
		},
	}
}

// ComplianceInput carries SCA check metadata for OCSF Security Finding mapping.
type ComplianceInput struct {
	EndpointID  string
	Hostname    string
	OS          string
	PolicyID    string
	PolicyName  string
	CheckID     int
	Title       string
	Description string
	Remediation string
	Result      string // passed|failed|not_applicable|error
	Compliance  map[string][]string
	MITRE       map[string][]string
	Timestamp   time.Time
}

// FromComplianceFinding maps an SCA check result to OCSF Security Finding (class 2001).
func FromComplianceFinding(in ComplianceInput, product Product) Envelope {
	ts := in.Timestamp
	if ts.IsZero() {
		ts = time.Now().UTC()
	}
	sevID, sev := complianceSeverity(in.Result)
	compliance := make(map[string]any, len(in.Compliance))
	for k, v := range in.Compliance {
		compliance[k] = v
	}
	if len(in.MITRE) > 0 {
		compliance["mitre"] = in.MITRE
	}
	return Envelope{
		ClassUID:     ClassUIDSecurityFinding,
		ClassName:    ClassSecurityFinding,
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
			LogName:     "sca",
			LogProvider: "compliance",
		},
		Finding: &Finding{
			UID:         uuid.NewString(),
			Title:       in.Title,
			Desc:        in.Description,
			Types:       []string{"Compliance", "SCA", in.Result},
			Remediation: in.Remediation,
			Compliance:  compliance,
		},
		Unmapped: map[string]any{
			"endpoint_id": in.EndpointID,
			"hostname":    in.Hostname,
			"os":          in.OS,
			"policy_id":   in.PolicyID,
			"policy_name": in.PolicyName,
			"check_id":    in.CheckID,
			"result":      in.Result,
		},
	}
}

// ComplianceScanInput summarizes one SCA scan run.
type ComplianceScanInput struct {
	EndpointID         string
	Hostname           string
	OS                 string
	Timestamp          time.Time
	Passed             int
	Failed             int
	Errors             int
	Skipped            int
	PoliciesTotal      int
	PoliciesApplicable int
	DurationMs         int64
}

// FromComplianceScan maps an SCA scan summary to OCSF Security Finding.
func FromComplianceScan(in ComplianceScanInput, product Product) Envelope {
	ts := in.Timestamp
	if ts.IsZero() {
		ts = time.Now().UTC()
	}
	sevID, sev := 1, "Informational"
	if in.Failed > 0 || in.Errors > 0 {
		sevID, sev = 3, "Medium"
	}
	return Envelope{
		ClassUID:     ClassUIDSecurityFinding,
		ClassName:    ClassSecurityFinding,
		CategoryUID:  2,
		CategoryName: "Findings",
		ActivityID:   2,
		ActivityName: "Update",
		SeverityID:   sevID,
		Severity:     sev,
		Time:         ts.UnixMilli(),
		Metadata: Metadata{
			Version:     SchemaVersion,
			Product:     product,
			LogName:     "sca",
			LogProvider: "compliance_scan",
		},
		Finding: &Finding{
			UID:   uuid.NewString(),
			Title: "SCA scan complete",
			Desc:  "Security Configuration Assessment scan summary",
			Types: []string{"Compliance", "SCA", "scan_summary"},
		},
		Unmapped: map[string]any{
			"endpoint_id":         in.EndpointID,
			"hostname":            in.Hostname,
			"os":                  in.OS,
			"passed":              in.Passed,
			"failed":              in.Failed,
			"errors":              in.Errors,
			"skipped":             in.Skipped,
			"policies_total":      in.PoliciesTotal,
			"policies_applicable": in.PoliciesApplicable,
			"duration_ms":         in.DurationMs,
		},
	}
}

func complianceSeverity(result string) (int, string) {
	switch strings.ToLower(strings.TrimSpace(result)) {
	case "failed":
		return 3, "Medium"
	case "error":
		return 4, "High"
	case "passed":
		return 1, "Informational"
	default:
		return 0, "Unknown"
	}
}
