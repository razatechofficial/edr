package alert

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/razatechofficial/edr/internal/schema"
	"github.com/razatechofficial/edr/pkg/events"
	"github.com/razatechofficial/edr/pkg/protocol"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// SchemaFromEvents maps a pipeline alert into schema.Alert, enriching from RawEvent when present.
func SchemaFromEvents(a *events.Alert, endpointID string) schema.Alert {
	if a == nil {
		return schema.Alert{}
	}
	al := schema.Alert{
		AlertID:     a.ID,
		RuleID:      a.RuleID,
		EndpointID:  endpointID,
		Title:       firstNonEmpty(a.Title, a.RuleName),
		Description: a.Description,
		Severity:    schema.Severity(a.Severity),
		Timestamp:   a.Timestamp,
		FilePath:    a.FilePath,
		FileSHA256:  a.FileSHA256,
	}
	enrichFromRawEvent(&al, a.RawEvent)
	return al
}

// ProtoFromEvents builds a gRPC Alert with flat fields and canonical OCSF JSON.
func ProtoFromEvents(a *events.Alert, endpointID, productVersion string) (*protocol.Alert, error) {
	if a == nil {
		return nil, fmt.Errorf("alert: nil events.Alert")
	}
	sch := SchemaFromEvents(a, endpointID)
	req := &protocol.Alert{
		AlertId:     sch.AlertID,
		RuleId:      sch.RuleID,
		RuleName:    a.RuleName,
		EndpointId:  endpointID,
		Severity:    eventsSeverityToProto(a.Severity),
		Title:       sch.Title,
		Description: sch.Description,
		Timestamp:   timestamppb.New(a.Timestamp.UTC()),
		Tags:        append([]string(nil), a.Tags...),
		ProcessPid:  int32(sch.ProcessPID),
		ProcessName: sch.ProcessName,
		ProcessPath: sch.ProcessPath,
		CommandLine: sch.CommandLine,
	}
	for _, m := range a.MITRE {
		req.Mitre = append(req.Mitre, &protocol.MITREAttack{
			TechniqueId:   m.TechniqueID,
			TechniqueName: m.TechniqueName,
			TacticId:      m.TacticID,
			TacticName:    m.TacticName,
		})
	}
	if raw, err := json.Marshal(a.RawEvent); err == nil {
		req.RawEvent = raw
	}
	if ocsfBytes, err := MarshalOCSF(sch, productVersion); err == nil {
		req.Ocsf = ocsfBytes
	}
	return req, nil
}

func enrichFromRawEvent(al *schema.Alert, raw interface{}) {
	if raw == nil {
		return
	}
	switch x := raw.(type) {
	case *schema.ProcessEvent:
		applyProcessEvent(al, x)
	case schema.ProcessEvent:
		applyProcessEvent(al, &x)
	case *schema.FileEvent:
		applyFileEvent(al, x)
	case schema.FileEvent:
		applyFileEvent(al, &x)
	case *schema.NetworkEvent:
		applyNetworkEvent(al, x)
	case schema.NetworkEvent:
		applyNetworkEvent(al, &x)
	case map[string]interface{}:
		enrichFromMap(al, x)
	default:
		if b, err := json.Marshal(raw); err == nil {
			var m map[string]interface{}
			if json.Unmarshal(b, &m) == nil {
				enrichFromMap(al, m)
			}
		}
	}
}

func applyProcessEvent(al *schema.Alert, pe *schema.ProcessEvent) {
	if pe == nil {
		return
	}
	if al.ProcessPID == 0 {
		al.ProcessPID = pe.PID
	}
	if al.ProcessName == "" {
		al.ProcessName = pe.ProcessName
	}
	if al.ProcessPath == "" {
		al.ProcessPath = pe.ProcessPath
	}
	if al.CommandLine == "" {
		al.CommandLine = pe.CommandLine
	}
	if al.User == "" {
		al.User = pe.User
	}
}

func applyFileEvent(al *schema.Alert, fe *schema.FileEvent) {
	if fe == nil {
		return
	}
	if al.FilePath == "" {
		al.FilePath = fe.Path
	}
	if al.FileSHA256 == "" {
		al.FileSHA256 = fe.Hash
	}
	if al.FileOperation == "" {
		al.FileOperation = fe.Operation
	}
	if al.ProcessPID == 0 {
		al.ProcessPID = fe.ActorPID
	}
}

func applyNetworkEvent(al *schema.Alert, ne *schema.NetworkEvent) {
	if ne == nil {
		return
	}
	if al.Protocol == "" {
		al.Protocol = ne.Protocol
	}
	if al.DestIP == "" {
		al.DestIP = ne.DestIP
	}
	if al.DestPort == 0 {
		al.DestPort = ne.DestPt
	}
	if al.SourceIP == "" {
		al.SourceIP = ne.SourceIP
	}
	if al.Domain == "" {
		al.Domain = ne.Domain
	}
}

func enrichFromMap(al *schema.Alert, m map[string]interface{}) {
	if al.ProcessPID == 0 {
		al.ProcessPID = mapIntField(m, "pid", "PID", "actor_pid", "ActorPID")
	}
	if al.ProcessName == "" {
		al.ProcessName = mapStringField(m, "process_name", "ProcessName", "Image")
	}
	if al.ProcessPath == "" {
		al.ProcessPath = mapStringField(m, "process_path", "ProcessPath", "ImagePath", "image")
	}
	if al.CommandLine == "" {
		al.CommandLine = mapStringField(m, "command_line", "CommandLine", "cmd_line")
	}
	if al.FilePath == "" {
		al.FilePath = mapStringField(m, "file_path", "FilePath", "path", "TargetFilename")
	}
	if al.FileSHA256 == "" {
		al.FileSHA256 = mapStringField(m, "file_sha256", "FileSHA256", "hash", "sha256")
	}
	if al.DestIP == "" {
		al.DestIP = mapStringField(m, "dest_ip", "DestIP", "destination_ip")
	}
	if al.Domain == "" {
		al.Domain = mapStringField(m, "domain", "Domain", "query", "hostname")
	}
}

func mapStringField(m map[string]interface{}, keys ...string) string {
	for _, want := range keys {
		for k, v := range m {
			if strings.EqualFold(k, want) {
				return strings.TrimSpace(fmt.Sprint(v))
			}
		}
	}
	return ""
}

func mapIntField(m map[string]interface{}, keys ...string) int {
	s := mapStringField(m, keys...)
	if s == "" {
		return 0
	}
	var n int
	_, _ = fmt.Sscanf(s, "%d", &n)
	return n
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

func eventsSeverityToProto(s events.Severity) protocol.Severity {
	switch s {
	case events.SeverityCritical:
		return protocol.Severity_SEVERITY_CRITICAL
	case events.SeverityHigh:
		return protocol.Severity_SEVERITY_HIGH
	case events.SeverityMedium:
		return protocol.Severity_SEVERITY_MEDIUM
	case events.SeverityLow:
		return protocol.Severity_SEVERITY_LOW
	default:
		return protocol.Severity_SEVERITY_INFO
	}
}
