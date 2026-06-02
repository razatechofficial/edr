package ocsf

import (
	"strings"
	"time"

	"github.com/google/uuid"
)

// AlertInput carries detection alert context for OCSF Detection Finding mapping.
type AlertInput struct {
	AlertID     string
	RuleID      string
	EndpointID  string
	Title       string
	Description string
	Severity    string
	Score       int
	Timestamp   time.Time

	ProcessPID  int
	ProcessName string
	ProcessPath string
	CommandLine string

	FilePath      string
	FileSHA256    string
	FileOperation string

	Protocol string
	DestIP   string
	DestPort int
	Domain   string
	SourceIP string
	URL      string

	User     string
	AuthType string
	Outcome  string

	// MITRE ATT&CK context
	TechniqueID   string
	TechniqueName string
	TacticID      string
	TacticName    string

	// Scoring / confidence
	Confidence float64
	RiskScore  int
	Disposition string

	// Host context
	Hostname string

	// Detection layer source
	DetectionLayer string
}

// FromDetectionAlert maps an agent detection alert to OCSF Detection Finding (class 2004).
func FromDetectionAlert(in AlertInput, product Product) Envelope {
	ts := in.Timestamp
	if ts.IsZero() {
		ts = time.Now().UTC()
	}
	sevID, sev := alertSeverity(in.Severity, in.Score)
	types := []string{"Detection", "EDR"}
	if in.RuleID != "" {
		types = append(types, in.RuleID)
	}

	activityID, activityName := fileOperationActivity(in.FileOperation)

	env := Envelope{
		ClassUID:     ClassUIDDetectionFinding,
		ClassName:    ClassDetectionFinding,
		CategoryUID:  2,
		CategoryName: "Findings",
		ActivityID:   activityID,
		ActivityName: activityName,
		SeverityID:   sevID,
		Severity:     sev,
		Time:         ts.UnixMilli(),
		Metadata: Metadata{
			Version:     SchemaVersion,
			Product:     product,
			LogName:     "detection",
			LogProvider: "alert",
		},
		Finding: &Finding{
			UID:   firstNonEmptyStr(in.AlertID, uuid.NewString()),
			Title: in.Title,
			Desc:  in.Description,
			Types: types,
		},
	}

	// Risk score (0-100 scale)
	riskScore := in.RiskScore
	if riskScore == 0 {
		riskScore = in.Score
	}
	if riskScore > 0 {
		env.RiskScore = riskScore
		env.RiskLevelID, env.RiskLevel = riskLevel(riskScore)
	}

	// Confidence (mapped to OCSF 0-3 scale from 0.0-1.0)
	if in.Confidence > 0 {
		env.ConfidenceID, env.Confidence = confidenceFromFloat(in.Confidence)
	}

	// Disposition
	if in.Disposition != "" {
		env.DispositionID, env.Disposition = dispositionFromString(in.Disposition)
	}

	// Device (endpoint context)
	if in.EndpointID != "" || in.Hostname != "" {
		env.Device = &Device{
			UID:      in.EndpointID,
			Hostname: in.Hostname,
			TypeID:   DeviceTypeEndpoint,
			Type:     "Endpoint",
		}
	}

	// MITRE ATT&CK mapping
	if in.TechniqueID != "" {
		atk := Attack{
			Technique: AttackTechnique{
				UID:  in.TechniqueID,
				Name: in.TechniqueName,
			},
			Version: "14.1",
		}
		if in.TacticID != "" {
			atk.Tactic = &AttackTactic{
				UID:  in.TacticID,
				Name: in.TacticName,
			}
		}
		env.Attacks = []Attack{atk}
	}

	// Actor (user who triggered)
	if in.User != "" {
		env.Actor = &Actor{
			User: &UserRecord{
				Name: in.User,
			},
		}
	}

	// Auth outcome -> status
	if in.Outcome != "" {
		env.StatusID, env.Status = outcomeToStatus(in.Outcome)
	}

	// Process context
	if proc := processFromInput(ProcessInput{
		PID:         in.ProcessPID,
		ProcessName: in.ProcessName,
		ProcessPath: in.ProcessPath,
		CommandLine: in.CommandLine,
		User:        in.User,
	}); proc != nil {
		env.Process = proc
	}

	// File context with proper hashes
	if path := strings.TrimSpace(in.FilePath); path != "" {
		f := &File{
			Name: filepathBase(path),
			Path: path,
			Type: "Regular File",
		}
		if in.FileSHA256 != "" {
			f.Hashes = []HashEntry{{
				Algorithm:   "SHA-256",
				AlgorithmID: HashAlgorithmSHA256,
				Value:       in.FileSHA256,
			}}
		}
		env.File = f
	}

	// Network endpoints
	if in.DestIP != "" || in.DestPort != 0 {
		env.DstEndpoint = &Endpoint{IP: in.DestIP, Port: in.DestPort}
	}
	if in.SourceIP != "" {
		env.SrcEndpoint = &Endpoint{IP: in.SourceIP}
	}

	// DNS query
	if in.Domain != "" {
		env.Query = &DNSQuery{Hostname: in.Domain}
	}

	// Observables: collect all indicators into canonical array
	env.Observables = buildObservables(in)

	return env
}

func buildObservables(in AlertInput) []Observable {
	var obs []Observable
	if in.Domain != "" {
		obs = append(obs, Observable{
			Name:   "domain",
			Type:   "Domain Name",
			TypeID: ObservableTypeDomainName,
			Value:  in.Domain,
		})
	}
	if in.URL != "" {
		obs = append(obs, Observable{
			Name:   "url",
			Type:   "URL",
			TypeID: ObservableTypeURL,
			Value:  in.URL,
		})
	}
	if in.DestIP != "" {
		obs = append(obs, Observable{
			Name:   "dst_ip",
			Type:   "IP Address",
			TypeID: ObservableTypeIPAddress,
			Value:  in.DestIP,
		})
	}
	if in.SourceIP != "" {
		obs = append(obs, Observable{
			Name:   "src_ip",
			Type:   "IP Address",
			TypeID: ObservableTypeIPAddress,
			Value:  in.SourceIP,
		})
	}
	if in.FileSHA256 != "" {
		obs = append(obs, Observable{
			Name:   "file_hash",
			Type:   "Hash",
			TypeID: ObservableTypeHash,
			Value:  in.FileSHA256,
		})
	}
	if in.ProcessName != "" {
		obs = append(obs, Observable{
			Name:   "process_name",
			Type:   "Process Name",
			TypeID: ObservableTypeProcess,
			Value:  in.ProcessName,
		})
	}
	if len(obs) == 0 {
		return nil
	}
	return obs
}

func fileOperationActivity(op string) (int, string) {
	switch strings.ToLower(strings.TrimSpace(op)) {
	case "create":
		return 1, "Create"
	case "read", "open":
		return 2, "Read"
	case "update", "write", "modify":
		return 3, "Update"
	case "delete", "remove":
		return 4, "Delete"
	case "rename", "move":
		return 5, "Rename"
	default:
		return 1, "Create"
	}
}

func riskLevel(score int) (int, string) {
	switch {
	case score >= 90:
		return RiskLevelCritical, "Critical"
	case score >= 70:
		return RiskLevelHigh, "High"
	case score >= 40:
		return RiskLevelMedium, "Medium"
	case score >= 20:
		return RiskLevelLow, "Low"
	default:
		return RiskLevelInfo, "Info"
	}
}

func confidenceFromFloat(c float64) (int, int) {
	switch {
	case c >= 0.8:
		return ConfidenceHigh, 3
	case c >= 0.5:
		return ConfidenceMedium, 2
	default:
		return ConfidenceLow, 1
	}
}

func dispositionFromString(d string) (int, string) {
	switch strings.ToLower(strings.TrimSpace(d)) {
	case "blocked", "block", "quarantined":
		return DispositionBlocked, "Blocked"
	case "allowed", "allow":
		return DispositionAllowed, "Allowed"
	default:
		return DispositionDetected, "Detected"
	}
}

func outcomeToStatus(outcome string) (int, string) {
	switch strings.ToLower(strings.TrimSpace(outcome)) {
	case "success", "ok":
		return 1, "Success"
	case "failure", "fail", "failed":
		return 2, "Failure"
	default:
		return 0, "Unknown"
	}
}

func alertSeverity(severity string, score int) (int, string) {
	switch strings.ToLower(strings.TrimSpace(severity)) {
	case "critical":
		return 5, "Critical"
	case "high":
		return 4, "High"
	case "medium":
		return 3, "Medium"
	case "low":
		return 2, "Low"
	case "info":
		return 1, "Informational"
	}
	switch {
	case score >= 90:
		return 5, "Critical"
	case score >= 75:
		return 4, "High"
	case score >= 55:
		return 3, "Medium"
	case score >= 35:
		return 2, "Low"
	default:
		return 1, "Informational"
	}
}

func filepathBase(path string) string {
	if i := strings.LastIndexAny(path, `/\`); i >= 0 && i+1 < len(path) {
		return path[i+1:]
	}
	return path
}

func firstNonEmptyStr(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}
