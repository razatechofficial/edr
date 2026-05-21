package ocsf

import (
	"fmt"
	"path/filepath"
	"strings"
)

// EnrichDetectionMap adds OCSF canonical fields, a nested ocsf envelope, and
// legacy Sigma/ECS aliases to a flat telemetry map. Original keys are preserved.
func EnrichDetectionMap(in map[string]interface{}) map[string]interface{} {
	if len(in) == 0 {
		return in
	}
	out := make(map[string]interface{}, len(in)+24)
	for k, v := range in {
		out[k] = v
	}

	eventType := strings.ToLower(stringField(in, "event_type", "type"))
	setIfAbsent(out, "ocsf.class_name", classNameForEventType(eventType))
	setIfAbsent(out, "ocsf.class_uid", classUIDForEventType(eventType))

	if v := stringField(in, "process_name", "ProcessName"); v != "" {
		setIfAbsent(out, "ocsf.process.file.name", v)
		setIfAbsent(out, "process.file.name", v)
		setIfAbsent(out, "process.name", v)
	}
	if v := stringField(in, "process_path", "ProcessPath", "Image"); v != "" {
		setIfAbsent(out, "ocsf.process.file.path", v)
		setIfAbsent(out, "process.file.path", v)
		setIfAbsent(out, "process.executable", v)
		setIfAbsent(out, "Image", v)
	}
	if v := stringField(in, "command_line", "CommandLine"); v != "" {
		setIfAbsent(out, "ocsf.process.cmd_line", v)
		setIfAbsent(out, "process.command_line", v)
		setIfAbsent(out, "CommandLine", v)
	}
	if v := intField(in, "pid", "PID"); v != 0 {
		setIfAbsent(out, "ocsf.process.pid", v)
		setIfAbsent(out, "process.pid", v)
	}
	if v := intField(in, "ppid", "PPID"); v != 0 {
		setIfAbsent(out, "ocsf.process.parent_process.pid", v)
		setIfAbsent(out, "process.parent.pid", v)
	}
	if v := stringField(in, "parent_name", "ParentName", "ParentImage"); v != "" {
		setIfAbsent(out, "process.parent.name", v)
		setIfAbsent(out, "ParentImage", v)
	}
	if v := stringField(in, "user", "User"); v != "" {
		setIfAbsent(out, "ocsf.process.user.name", v)
		setIfAbsent(out, "process.user.name", v)
	}

	if v := stringField(in, "path", "Path", "file_path", "TargetFilename"); v != "" {
		setIfAbsent(out, "ocsf.file.path", v)
		setIfAbsent(out, "file.path", v)
		setIfAbsent(out, "TargetFilename", v)
		setIfAbsent(out, "file.name", filepath.Base(v))
	}
	if v := stringField(in, "operation", "Operation", "file_operation"); v != "" {
		setIfAbsent(out, "ocsf.file.activity_name", v)
		setIfAbsent(out, "file.action", v)
	}

	if v := stringField(in, "dest_ip", "DstIP", "DestinationIp", "dst_addr"); v != "" {
		setIfAbsent(out, "ocsf.dst_endpoint.ip", v)
		setIfAbsent(out, "destination.ip", v)
		setIfAbsent(out, "DestinationIp", v)
	}
	if v := intField(in, "dest_port", "DstPort", "DestinationPort", "dst_port"); v != 0 {
		setIfAbsent(out, "ocsf.dst_endpoint.port", v)
		setIfAbsent(out, "destination.port", v)
		setIfAbsent(out, "DestinationPort", v)
	}
	if v := stringField(in, "src_ip", "SrcIP", "SourceIp", "source_ip"); v != "" {
		setIfAbsent(out, "ocsf.src_endpoint.ip", v)
		setIfAbsent(out, "source.ip", v)
		setIfAbsent(out, "SourceIp", v)
	}
	if v := stringField(in, "protocol", "Protocol"); v != "" {
		setIfAbsent(out, "network.transport", v)
	}
	if v := stringField(in, "domain", "Domain", "DNSQuery", "QueryName"); v != "" {
		setIfAbsent(out, "dns.question.name", v)
		setIfAbsent(out, "QueryName", v)
	}

	if v := stringField(in, "registry_path", "RegistryPath", "TargetObject"); v != "" {
		setIfAbsent(out, "registry.path", v)
		setIfAbsent(out, "TargetObject", v)
	}
	if v := stringField(in, "registry_value", "RegistryValue", "Details"); v != "" {
		setIfAbsent(out, "registry.value", v)
		setIfAbsent(out, "Details", v)
	}

	if v := stringField(in, "hostname", "Hostname"); v != "" {
		setIfAbsent(out, "ocsf.device.hostname", v)
	}
	if v := stringField(in, "endpoint_id", "EndpointID"); v != "" {
		setIfAbsent(out, "ocsf.device.uid", v)
	}
	if v := stringField(in, "os", "OS"); v != "" {
		setIfAbsent(out, "ocsf.device.os.name", v)
	}

	enrichDarwinSigmaFields(out)
	applyCanonicalOCSFFields(out)
	if existing, ok := in["ocsf"].(map[string]interface{}); ok && len(existing) > 0 {
		out["ocsf"] = existing
	} else if env := BuildDetectionEnvelope(in); len(env) > 0 {
		out["ocsf"] = env
	}

	return out
}

func classNameForEventType(t string) string {
	switch t {
	case "process":
		return ClassProcessActivity
	case "file", "file_access":
		return ClassFileActivity
	case "network":
		return ClassNetworkActivity
	case "auth", "authentication":
		return ClassAuthentication
	case "fork":
		return ClassProcessActivity
	case "registry":
		return ClassRegistryKeyActivity
	case "injection":
		return ClassProcessActivity
	case "compliance":
		return ClassSecurityFinding
	default:
		return ""
	}
}

func classUIDForEventType(t string) int {
	switch t {
	case "process":
		return ClassUIDProcessActivity
	case "file", "file_access":
		return ClassUIDFileActivity
	case "network":
		return ClassUIDNetworkActivity
	case "auth", "authentication":
		return ClassUIDAuthentication
	case "fork", "injection":
		return ClassUIDProcessActivity
	case "registry":
		return ClassUIDRegistryKeyActivity
	case "compliance":
		return ClassUIDSecurityFinding
	default:
		return 0
	}
}

func setIfAbsent(m map[string]interface{}, key string, val interface{}) {
	if val == nil {
		return
	}
	if s, ok := val.(string); ok && s == "" {
		return
	}
	if _, exists := m[key]; !exists {
		m[key] = val
	}
}

func stringField(m map[string]interface{}, keys ...string) string {
	for _, want := range keys {
		for k, v := range m {
			if strings.EqualFold(k, want) {
				return strings.TrimSpace(fmt.Sprint(v))
			}
		}
	}
	return ""
}

func intField(m map[string]interface{}, keys ...string) int {
	s := stringField(m, keys...)
	if s == "" {
		return 0
	}
	var n int
	_, _ = fmt.Sscanf(s, "%d", &n)
	return n
}
