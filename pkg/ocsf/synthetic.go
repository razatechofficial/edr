package ocsf

import (
	"strings"

	"github.com/google/uuid"
)

// activityFindingInput builds Security Finding envelopes for agent telemetry signals.
type activityFindingInput struct {
	EndpointID   string
	Hostname     string
	OS           string
	Timestamp    int64
	Title        string
	Description  string
	Types        []string
	SeverityID   int
	Severity     string
	ActivityName string
	Process      *Process
	File         *File
	Unmapped     map[string]any
}

func fromActivityFinding(in activityFindingInput, product Product) Envelope {
	ts := in.Timestamp
	if ts == 0 {
		ts = timeNowMillis()
	}
	sevID, sev := in.SeverityID, in.Severity
	if sevID == 0 {
		sevID, sev = 3, "Medium"
	}
	activity := strings.TrimSpace(in.ActivityName)
	if activity == "" {
		activity = "Create"
	}
	return Envelope{
		ClassUID:     ClassUIDSecurityFinding,
		ClassName:    ClassSecurityFinding,
		CategoryUID:  2,
		CategoryName: "Findings",
		ActivityID:   1,
		ActivityName: activity,
		SeverityID:   sevID,
		Severity:     sev,
		Time:         ts,
		Metadata: Metadata{
			Version: SchemaVersion,
			Product: product,
		},
		Finding: &Finding{
			UID:   uuid.NewString(),
			Title: in.Title,
			Desc:  in.Description,
			Types: in.Types,
		},
		Process:  in.Process,
		File:     in.File,
		Unmapped: mergeUnmapped(in.EndpointID, in.Hostname, in.OS, in.Unmapped),
	}
}

func mergeUnmapped(endpointID, hostname, osName string, extra map[string]any) map[string]any {
	out := map[string]any{}
	if endpointID != "" {
		out["endpoint_id"] = endpointID
	}
	if hostname != "" {
		out["hostname"] = hostname
	}
	if osName != "" {
		out["os"] = osName
	}
	for k, v := range extra {
		out[k] = v
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// CredentialInput is a credential access telemetry snapshot.
type CredentialInput struct {
	EndpointID    string
	Hostname      string
	OS            string
	Timestamp     int64
	Technique     string
	SourcePID     int
	SourceProcess string
	TargetPath    string
	AccessMask    uint32
	Severity      string
}

// FromCredentialAccess maps credential access telemetry to Process Activity.
func FromCredentialAccess(in CredentialInput, product Product) Envelope {
	ts := in.Timestamp
	if ts == 0 {
		ts = timeNowMillis()
	}
	return Envelope{
		ClassUID:     ClassUIDProcessActivity,
		ClassName:    ClassProcessActivity,
		CategoryUID:  1,
		CategoryName: "System Activity",
		ActivityID:   5,
		ActivityName: "Access",
		Time:         ts,
		Metadata: Metadata{
			Version: SchemaVersion,
			Product: product,
		},
		Process: processFromInput(ProcessInput{
			ProcessName: in.SourceProcess,
			ProcessPath: in.TargetPath,
			CommandLine: in.Technique,
			PID:         in.SourcePID,
		}),
		Unmapped: mergeUnmapped(in.EndpointID, in.Hostname, in.OS, map[string]any{
			"activity_kind": "credential_access",
			"technique":     in.Technique,
			"access_mask":   in.AccessMask,
			"severity":      in.Severity,
		}),
	}
}

// ContainerInput is a container/cgroup telemetry snapshot.
type ContainerInput struct {
	EndpointID  string
	Hostname    string
	OS          string
	Timestamp   int64
	Operation   string
	PID         int
	ProcessName string
	Path        string
	Mode        uint32
}

// FromContainer maps container telemetry to Process Activity.
func FromContainer(in ContainerInput, product Product) Envelope {
	ts := in.Timestamp
	if ts == 0 {
		ts = timeNowMillis()
	}
	return Envelope{
		ClassUID:     ClassUIDProcessActivity,
		ClassName:    ClassProcessActivity,
		CategoryUID:  1,
		CategoryName: "System Activity",
		ActivityID:   1,
		ActivityName: in.Operation,
		Time:         ts,
		Metadata: Metadata{
			Version: SchemaVersion,
			Product: product,
		},
		Process: processFromInput(ProcessInput{
			PID:         in.PID,
			ProcessName: in.ProcessName,
			ProcessPath: in.Path,
		}),
		Unmapped: mergeUnmapped(in.EndpointID, in.Hostname, in.OS, map[string]any{
			"activity_kind": "container",
			"mode":          in.Mode,
		}),
	}
}

// SecPolicyInput is a security policy change telemetry snapshot.
type SecPolicyInput struct {
	EndpointID string
	Hostname   string
	OS         string
	Timestamp  int64
	Operation  string
	PID        int
	Flags      uint64
}

// FromSecPolicy maps security policy telemetry to a Security Finding.
func FromSecPolicy(in SecPolicyInput, product Product) Envelope {
	return fromActivityFinding(activityFindingInput{
		EndpointID:   in.EndpointID,
		Hostname:     in.Hostname,
		OS:           in.OS,
		Timestamp:    in.Timestamp,
		Title:        "Security policy change",
		Description:  in.Operation,
		Types:        []string{"Configuration", "SecurityPolicy"},
		SeverityID:   3,
		Severity:     "Medium",
		ActivityName: in.Operation,
		Process:      processFromInput(ProcessInput{PID: in.PID}),
		Unmapped: map[string]any{
			"activity_kind": "security_policy",
			"flags":         in.Flags,
		},
	}, product)
}

// TamperInput is an agent tamper telemetry snapshot.
type TamperInput struct {
	EndpointID string
	Hostname   string
	OS         string
	Timestamp  int64
	Component  string
	ProgramID  uint32
	Message    string
}

// FromTamper maps tamper telemetry to a Security Finding.
func FromTamper(in TamperInput, product Product) Envelope {
	return fromActivityFinding(activityFindingInput{
		EndpointID:   in.EndpointID,
		Hostname:     in.Hostname,
		OS:           in.OS,
		Timestamp:    in.Timestamp,
		Title:        "Agent tamper signal",
		Description:  firstNonEmptyStr(in.Message, in.Component),
		Types:        []string{"Tamper", "Agent"},
		SeverityID:   4,
		Severity:     "High",
		ActivityName: "Update",
		Unmapped: map[string]any{
			"activity_kind": "tamper",
			"component":     in.Component,
			"program_id":    in.ProgramID,
		},
	}, product)
}

// PersistenceInput is a persistence mechanism telemetry snapshot.
type PersistenceInput struct {
	EndpointID     string
	Hostname       string
	OS             string
	Timestamp      int64
	Technique      string
	ExecutablePath string
	ItemType       string
	IsLegacy       bool
	IsManaged      bool
	PID            int
	ProcessPath    string
}

// FromPersistence maps persistence telemetry to a Security Finding.
func FromPersistence(in PersistenceInput, product Product) Envelope {
	return fromActivityFinding(activityFindingInput{
		EndpointID:   in.EndpointID,
		Hostname:     in.Hostname,
		OS:           in.OS,
		Timestamp:    in.Timestamp,
		Title:        "Persistence mechanism detected",
		Description:  firstNonEmptyStr(in.Technique, in.ExecutablePath),
		Types:        []string{"Persistence", in.Technique},
		SeverityID:   4,
		Severity:     "High",
		ActivityName: "Create",
		Process: processFromInput(ProcessInput{
			PID:         in.PID,
			ProcessPath: firstNonEmptyStr(in.ProcessPath, in.ExecutablePath),
		}),
		Unmapped: map[string]any{
			"activity_kind": "persistence",
			"item_type":     in.ItemType,
			"legacy":        in.IsLegacy,
			"managed":       in.IsManaged,
		},
	}, product)
}

// PrivacyInput is a privacy-sensitive access telemetry snapshot.
type PrivacyInput struct {
	EndpointID       string
	Hostname           string
	OS                 string
	Timestamp          int64
	Operation          string
	Service            string
	AuthValue          int
	AuthReason         string
	AccessingPID       int
	AccessingProcess   string
}

// FromPrivacy maps privacy access telemetry to Process Activity.
func FromPrivacy(in PrivacyInput, product Product) Envelope {
	ts := in.Timestamp
	if ts == 0 {
		ts = timeNowMillis()
	}
	return Envelope{
		ClassUID:     ClassUIDProcessActivity,
		ClassName:    ClassProcessActivity,
		CategoryUID:  1,
		CategoryName: "System Activity",
		ActivityID:   5,
		ActivityName: in.Operation,
		Time:         ts,
		Metadata: Metadata{
			Version: SchemaVersion,
			Product: product,
		},
		Process: processFromInput(ProcessInput{
			PID:         in.AccessingPID,
			ProcessName: in.AccessingProcess,
		}),
		Unmapped: mergeUnmapped(in.EndpointID, in.Hostname, in.OS, map[string]any{
			"activity_kind": "privacy",
			"service":       in.Service,
			"auth_value":    in.AuthValue,
			"auth_reason":   in.AuthReason,
		}),
	}
}

// GatekeeperInput is a Gatekeeper bypass telemetry snapshot.
type GatekeeperInput struct {
	EndpointID    string
	Hostname        string
	OS              string
	Timestamp       int64
	FilePath        string
	PID             int
	ProcessPath     string
	SigningStatus   string
}

// FromGatekeeper maps Gatekeeper bypass telemetry to a Security Finding.
func FromGatekeeper(in GatekeeperInput, product Product) Envelope {
	return fromActivityFinding(activityFindingInput{
		EndpointID:   in.EndpointID,
		Hostname:     in.Hostname,
		OS:           in.OS,
		Timestamp:    in.Timestamp,
		Title:        "Gatekeeper bypass attempt",
		Description:  firstNonEmptyStr(in.FilePath, in.ProcessPath),
		Types:        []string{"Gatekeeper", "Codesign"},
		SeverityID:   4,
		Severity:     "High",
		ActivityName: "Other",
		Process: processFromInput(ProcessInput{
			PID:         in.PID,
			ProcessPath: in.ProcessPath,
		}),
		File: &File{
			Name: filepathBase(in.FilePath),
			Path: in.FilePath,
		},
		Unmapped: map[string]any{
			"activity_kind":  "gatekeeper",
			"signing_status": in.SigningStatus,
		},
	}, product)
}

// DroppedInput is a dropped-events gap telemetry snapshot.
type DroppedInput struct {
	EndpointID string
	Hostname   string
	OS         string
	Timestamp  int64
	EventClass string
	GapSize    uint64
	LastSeq    uint64
	CurrentSeq uint64
}

// FromDropped maps dropped event gap telemetry to a Security Finding.
func FromDropped(in DroppedInput, product Product) Envelope {
	return fromActivityFinding(activityFindingInput{
		EndpointID:   in.EndpointID,
		Hostname:     in.Hostname,
		OS:           in.OS,
		Timestamp:    in.Timestamp,
		Title:        "Telemetry gap detected",
		Description:  in.EventClass,
		Types:        []string{"Telemetry", "DroppedEvents"},
		SeverityID:   2,
		Severity:     "Low",
		ActivityName: "Update",
		Unmapped: map[string]any{
			"activity_kind": "dropped_events",
			"event_class":   in.EventClass,
			"gap_size":      in.GapSize,
			"last_seq":      in.LastSeq,
			"current_seq":   in.CurrentSeq,
		},
	}, product)
}

// TIStatusInput is a threat-intel pipeline status snapshot.
type TIStatusInput struct {
	EndpointID string
	Hostname   string
	OS         string
	Timestamp  int64
	Status     string
	Reason     string
}

// FromTIStatus maps TI pipeline status to a Security Finding.
func FromTIStatus(in TIStatusInput, product Product) Envelope {
	return fromActivityFinding(activityFindingInput{
		EndpointID:   in.EndpointID,
		Hostname:     in.Hostname,
		OS:           in.OS,
		Timestamp:    in.Timestamp,
		Title:        "Threat intelligence status",
		Description:  firstNonEmptyStr(in.Reason, in.Status),
		Types:        []string{"ThreatIntelligence", in.Status},
		SeverityID:   2,
		Severity:     "Low",
		ActivityName: "Update",
		Unmapped: map[string]any{
			"activity_kind": "ti_status",
			"status":        in.Status,
		},
	}, product)
}

// FeatureStatusInput is a collector feature coverage snapshot.
type FeatureStatusInput struct {
	EndpointID string
	Hostname   string
	OS         string
	Timestamp  int64
	Features   map[string]bool
	Degraded   []string
}

// FromFeatureStatus maps feature coverage status to a Security Finding.
func FromFeatureStatus(in FeatureStatusInput, product Product) Envelope {
	return fromActivityFinding(activityFindingInput{
		EndpointID:   in.EndpointID,
		Hostname:     in.Hostname,
		OS:           in.OS,
		Timestamp:    in.Timestamp,
		Title:        "Agent feature coverage",
		Description:  "Collector feature status snapshot",
		Types:        []string{"Agent", "FeatureStatus"},
		SeverityID:   1,
		Severity:     "Informational",
		ActivityName: "Update",
		Unmapped: map[string]any{
			"activity_kind": "feature_status",
			"features":      in.Features,
			"degraded":      in.Degraded,
		},
	}, product)
}
