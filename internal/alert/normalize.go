package alert

import "github.com/razatechofficial/edr/internal/schema"

// WithOCSFContext fills empty flat alert fields from an attached OCSF envelope.
func WithOCSFContext(a schema.Alert) schema.Alert {
	if len(a.OCSF) == 0 {
		return a
	}
	fromOCSF, err := alertFromOCSFMap(a.OCSF)
	if err != nil {
		return a
	}
	return mergeAlertFields(a, fromOCSF)
}

func mergeAlertFields(primary, fallback schema.Alert) schema.Alert {
	out := primary
	if out.AlertID == "" {
		out.AlertID = fallback.AlertID
	}
	if out.RuleID == "" {
		out.RuleID = fallback.RuleID
	}
	if out.EndpointID == "" {
		out.EndpointID = fallback.EndpointID
	}
	if out.Title == "" {
		out.Title = fallback.Title
	}
	if out.Description == "" {
		out.Description = fallback.Description
	}
	if out.Severity == "" {
		out.Severity = fallback.Severity
	}
	if out.Score == 0 {
		out.Score = fallback.Score
	}
	if out.Timestamp.IsZero() {
		out.Timestamp = fallback.Timestamp
	}
	if out.ProcessPID == 0 {
		out.ProcessPID = fallback.ProcessPID
	}
	if out.ProcessName == "" {
		out.ProcessName = fallback.ProcessName
	}
	if out.ProcessPath == "" {
		out.ProcessPath = fallback.ProcessPath
	}
	if out.CommandLine == "" {
		out.CommandLine = fallback.CommandLine
	}
	if out.FilePath == "" {
		out.FilePath = fallback.FilePath
	}
	if out.FileSHA256 == "" {
		out.FileSHA256 = fallback.FileSHA256
	}
	if out.FileOperation == "" {
		out.FileOperation = fallback.FileOperation
	}
	if out.Protocol == "" {
		out.Protocol = fallback.Protocol
	}
	if out.DestIP == "" {
		out.DestIP = fallback.DestIP
	}
	if out.DestPort == 0 {
		out.DestPort = fallback.DestPort
	}
	if out.Domain == "" {
		out.Domain = fallback.Domain
	}
	if out.SourceIP == "" {
		out.SourceIP = fallback.SourceIP
	}
	if out.URL == "" {
		out.URL = fallback.URL
	}
	if out.User == "" {
		out.User = fallback.User
	}
	if out.AuthType == "" {
		out.AuthType = fallback.AuthType
	}
	if out.Outcome == "" {
		out.Outcome = fallback.Outcome
	}
	if out.Hostname == "" {
		out.Hostname = fallback.Hostname
	}
	if len(out.OCSF) == 0 {
		out.OCSF = fallback.OCSF
	}
	return out
}
