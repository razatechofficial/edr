package collector

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"time"

	"github.com/razatechofficial/edr/internal/schema"
)

// MapKernelJSONToTelemetry maps kernel driver JSON (Linux eBPF JSON path, ESF,
// ETW envelopes) into schema telemetry. Returns nil if the payload is not recognized.
func MapKernelJSONToTelemetry(data []byte, endpointID, hostname, goos string) *Telemetry {
	var raw map[string]interface{}
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil
	}

	evType, _ := raw["type"].(string)
	evType = strings.TrimSpace(strings.ToLower(evType))
	if evType == "" {
		return nil
	}

	ts := parseKernelJSONTime(raw)
	base := schema.BaseEvent{
		SchemaVersion: schema.SchemaVersionV1,
		EndpointID:    endpointID,
		Timestamp:     ts,
		Hostname:      hostname,
		OS:            goos,
	}

	switch evType {
	case "process":
		base.EventType = schema.EventProcess
		pe := &schema.ProcessEvent{BaseEvent: base}
		pe.PID = jsonInt(raw, "pid", "child_pid", "exit_pid")
		pe.ChildPID = jsonInt(raw, "child_pid")
		pe.PPID = jsonInt(raw, "ppid", "parent_pid")
		pe.ProcessName = firstNonEmpty(
			jsonString(raw, "process_name"),
			jsonString(raw, "comm"),
			filepath.Base(jsonString(raw, "path")),
		)
		pe.ProcessPath = firstNonEmpty(
			jsonString(raw, "process_path"),
			jsonString(raw, "path"),
			jsonString(raw, "image_name"),
		)
		pe.CommandLine = firstNonEmpty(
			jsonString(raw, "command_line"),
			jsonString(raw, "args"),
		)
		pe.SigningTeamID = jsonString(raw, "signing_team_id")
		pe.ImageCDHash = jsonString(raw, "image_cdhash")
		pe.SigningFlags = jsonUint32(raw, "signing_flags")
		pe.ImageSHA256 = jsonString(raw, "image_sha256")
		pe.TLSClientJA3 = firstNonEmpty(jsonString(raw, "tls_client_ja3"), jsonString(raw, "ja3"))
		pe.CloneFlags = jsonUint64(raw, "clone_flags")
		pe.UnshareFlags = jsonUint64(raw, "unshare_flags")
		pe.MadviseAdvice = int32(jsonInt(raw, "madvise_advice"))
		return &Telemetry{Process: pe}

	case "file":
		base.EventType = schema.EventFile
		fe := &schema.FileEvent{BaseEvent: base}
		fe.Path = firstNonEmpty(jsonString(raw, "path"), jsonString(raw, "file_name"))
		fe.Operation = jsonString(raw, "operation")
		if fe.Operation == "" {
			fe.Operation = "event"
		}
		fe.ActorPID = jsonInt(raw, "pid")
		return &Telemetry{File: fe}

	case "network":
		base.EventType = schema.EventNetwork
		ne := &schema.NetworkEvent{BaseEvent: base, PID: jsonInt(raw, "pid")}
		ne.Protocol = jsonString(raw, "protocol")
		ne.SourceIP = firstNonEmpty(jsonString(raw, "source_ip"), jsonString(raw, "src"))
		ne.DestIP = firstNonEmpty(jsonString(raw, "dest_ip"), jsonString(raw, "dst"), jsonString(raw, "dst_addr"))
		ne.SourcePt = jsonInt(raw, "source_port", "src_port")
		ne.DestPt = jsonInt(raw, "dest_port", "dst_port")
		return &Telemetry{Network: ne}

	case "dns":
		base.EventType = schema.EventNetwork
		ne := &schema.NetworkEvent{BaseEvent: base, PID: jsonInt(raw, "pid"), Protocol: "dns"}
		ne.Domain = firstNonEmpty(jsonString(raw, "query"), jsonString(raw, "domain"), jsonString(raw, "query_name"))
		return &Telemetry{Network: ne}

	case "module", "mount", "signal", "ptrace", "memory", "registry":
		base.EventType = schema.EventProcess
		pe := &schema.ProcessEvent{BaseEvent: base}
		pe.PID = jsonInt(raw, "pid")
		pe.ProcessName = evType
		pe.ProcessPath = firstNonEmpty(jsonString(raw, "path"), jsonString(raw, "module_path"))
		pe.CommandLine = jsonString(raw, "message")
		return &Telemetry{Process: pe}

	case "namespace":
		base.EventType = schema.EventProcess
		pe := &schema.ProcessEvent{BaseEvent: base}
		pe.PID = jsonInt(raw, "pid")
		pe.ProcessName = "namespace"
		pe.ProcessPath = jsonString(raw, "process_name")
		pe.UnshareFlags = jsonUint64(raw, "unshare_flags")
		pe.CommandLine = jsonString(raw, "command_line")
		return &Telemetry{Process: pe}

	case "madvise":
		base.EventType = schema.EventProcess
		pe := &schema.ProcessEvent{BaseEvent: base}
		pe.PID = jsonInt(raw, "pid")
		pe.ProcessName = "madvise"
		pe.ProcessPath = jsonString(raw, "process_name")
		pe.MadviseAdvice = int32(jsonInt(raw, "madvise_advice"))
		pe.CommandLine = jsonString(raw, "command_line")
		return &Telemetry{Process: pe}

	case "wmi", "powershell", "pipe", "bits", "task":
		base.EventType = schema.EventProcess
		pe := &schema.ProcessEvent{BaseEvent: base}
		pe.PID = jsonInt(raw, "pid")
		pe.ProcessName = evType
		pe.ProcessPath = jsonString(raw, "path")
		pe.CommandLine = firstNonEmpty(
			jsonString(raw, "etw_user_data_prefix_hex"),
			jsonString(raw, "message"),
		)
		return &Telemetry{Process: pe}

	default:
		return nil
	}
}

func parseKernelJSONTime(raw map[string]interface{}) time.Time {
	if v, ok := raw["timestamp"].(string); ok {
		if t, err := time.Parse(time.RFC3339Nano, v); err == nil {
			return t.UTC()
		}
		if t, err := time.Parse(time.RFC3339, v); err == nil {
			return t.UTC()
		}
	}
	return time.Now().UTC()
}

func jsonString(m map[string]interface{}, key string) string {
	v, ok := m[key]
	if !ok || v == nil {
		return ""
	}
	switch s := v.(type) {
	case string:
		return s
	default:
		return ""
	}
}

func jsonUint32(m map[string]interface{}, key string) uint32 {
	v, ok := m[key]
	if !ok || v == nil {
		return 0
	}
	switch x := v.(type) {
	case float64:
		return uint32(x)
	case int:
		return uint32(x)
	case int64:
		return uint32(x)
	case uint64:
		return uint32(x)
	case uint32:
		return x
	case json.Number:
		i, _ := x.Int64()
		return uint32(i)
	}
	return 0
}

func jsonUint64(m map[string]interface{}, keys ...string) uint64 {
	for _, key := range keys {
		v, ok := m[key]
		if !ok || v == nil {
			continue
		}
		switch x := v.(type) {
		case float64:
			return uint64(x)
		case int:
			return uint64(x)
		case int64:
			return uint64(x)
		case uint64:
			return x
		case uint32:
			return uint64(x)
		case json.Number:
			i, _ := x.Int64()
			return uint64(i)
		}
	}
	return 0
}

func jsonInt(m map[string]interface{}, keys ...string) int {
	for _, key := range keys {
		v, ok := m[key]
		if !ok || v == nil {
			continue
		}
		switch x := v.(type) {
		case float64:
			return int(x)
		case int:
			return x
		case int64:
			return int(x)
		case uint64:
			return int(x)
		case uint32:
			return int(x)
		case json.Number:
			i, _ := x.Int64()
			return int(i)
		}
	}
	return 0
}

func firstNonEmpty(vals ...string) string {
	for _, s := range vals {
		if strings.TrimSpace(s) != "" {
			return s
		}
	}
	return ""
}
