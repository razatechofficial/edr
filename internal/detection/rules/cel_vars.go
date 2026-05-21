package rules

import (
	"fmt"
	"strings"

	"github.com/google/cel-go/cel"
)

// celVarNames lists CEL activation keys. Primary names follow OCSF 1.3 attributes;
// legacy flat names are kept for backward-compatible rules.
var celVarNames = []string{
	"event_type",
	// OCSF primary (flat form for CEL string/int ops).
	"class_uid",
	"class_name",
	"process_cmd_line",
	"process_file_name",
	"process_file_path",
	"file_path_ocsf",
	"destination_ip",
	"destination_port",
	"source_ip_ocsf",
	"dns_query",
	"registry_path",
	"registry_value",
	// Legacy flat names (Sigma-era).
	"process_name",
	"process_path",
	"command_line",
	"pid",
	"ppid",
	"parent_name",
	"user",
	"file_path",
	"file_operation",
	"file_hash",
	"source_ip",
	"dest_ip",
	"source_port",
	"dest_port",
	"protocol",
	"domain",
	"auth_type",
	"auth_outcome",
	"hostname",
	"os",
	"severity",
	// Deprecated aliases (still populated).
	"ocsf_class_uid",
	"ocsf_class_name",
}

func newCELEnv() (*cel.Env, error) {
	opts := make([]cel.EnvOption, 0, len(celVarNames)+1)
	for _, name := range celVarNames {
		switch name {
		case "pid", "ppid", "source_port", "dest_port", "destination_port", "class_uid", "ocsf_class_uid":
			opts = append(opts, cel.Variable(name, cel.IntType))
		default:
			opts = append(opts, cel.Variable(name, cel.StringType))
		}
	}
	opts = append(opts, cel.Variable("ocsf", cel.DynType))
	return cel.NewEnv(opts...)
}

func activationFromMap(vars map[string]interface{}) map[string]interface{} {
	out := make(map[string]interface{}, len(celVarNames)+12)
	for _, name := range celVarNames {
		switch name {
		case "pid", "ppid", "source_port", "dest_port", "destination_port", "class_uid", "ocsf_class_uid":
			out[name] = int64(0)
		default:
			out[name] = ""
		}
	}

	alias := map[string][]string{
		"class_uid":         {"class_uid", "ocsf.class_uid", "ocsf_class_uid"},
		"class_name":        {"class_name", "ocsf.class_name", "ocsf_class_name"},
		"process_cmd_line":  {"process_cmd_line", "command_line", "CommandLine", "process.command_line", "ocsf.process.cmd_line"},
		"process_file_name": {"process_file_name", "process_name", "ProcessName", "process.file.name", "ocsf.process.file.name"},
		"process_file_path": {"process_file_path", "process_path", "ProcessPath", "Image", "process.file.path", "ocsf.process.file.path"},
		"file_path_ocsf":    {"file_path_ocsf", "file.path", "ocsf.file.path", "file_path", "path", "TargetFilename"},
		"destination_ip":    {"destination_ip", "dest_ip", "DstIP", "DestinationIp", "destination.ip", "ocsf.dst_endpoint.ip"},
		"destination_port":  {"destination_port", "dest_port", "DstPort", "DestinationPort", "destination.port", "ocsf.dst_endpoint.port"},
		"source_ip_ocsf":    {"source_ip_ocsf", "source_ip", "SrcIP", "SourceIp", "source.ip", "ocsf.src_endpoint.ip"},
		"dns_query":           {"dns_query", "domain", "Domain", "QueryName", "dns.question.name"},
		"registry_path":       {"registry_path", "RegistryPath", "TargetObject", "registry.path"},
		"registry_value":      {"registry_value", "RegistryValue", "Details", "registry.value"},
		"ocsf_class_uid":      {"ocsf_class_uid", "class_uid", "ocsf.class_uid"},
		"ocsf_class_name":     {"ocsf_class_name", "class_name", "ocsf.class_name"},
		"process_name":        {"process_name", "ProcessName", "process.file.name", "process_file_name"},
		"process_path":        {"process_path", "ProcessPath", "Image", "process.file.path", "process_file_path"},
		"command_line":        {"command_line", "CommandLine", "process.command_line", "process_cmd_line"},
		"parent_name":         {"parent_name", "ParentName", "ParentImage", "process.parent.name"},
		"file_path":           {"file_path", "path", "Path", "TargetFilename", "file_path_ocsf"},
		"file_operation":      {"file_operation", "operation", "Operation", "file.action", "ocsf.file.activity_name"},
		"dest_ip":             {"dest_ip", "DstIP", "DestinationIp", "destination.ip", "destination_ip"},
		"dest_port":           {"dest_port", "DstPort", "DestinationPort", "destination.port", "destination_port"},
		"source_ip":           {"source_ip", "SrcIP", "SourceIp", "source.ip", "source_ip_ocsf"},
		"domain":              {"domain", "Domain", "QueryName", "dns.question.name", "dns_query"},
		"event_type":          {"event_type", "type", "EventType"},
		"hostname":            {"hostname", "Hostname", "ocsf.device.hostname"},
		"os":                  {"os", "OS", "ocsf.device.os.name"},
		"user":                {"user", "User", "ocsf.process.user.name"},
		"protocol":            {"protocol", "Protocol", "network.transport"},
		"auth_type":           {"auth_type", "AuthType"},
		"auth_outcome":        {"auth_outcome", "AuthOutcome", "outcome"},
		"severity":            {"severity", "Severity"},
		"file_hash":           {"file_hash", "FileHash", "hash", "Hashes"},
	}

	for _, name := range celVarNames {
		if keys, ok := alias[name]; ok {
			if v, found := coalesceVar(vars, keys...); found {
				out[name] = v
			}
			continue
		}
		if v, ok := vars[name]; ok {
			out[name] = normalizeCELValue(v)
		}
	}

	if ocsfObj, ok := vars["ocsf"]; ok {
		out["ocsf"] = ocsfObj
	}

	for k, v := range vars {
		if _, exists := out[k]; !exists {
			out[k] = normalizeCELValue(v)
		}
	}
	return out
}

func coalesceVar(vars map[string]interface{}, keys ...string) (interface{}, bool) {
	for _, want := range keys {
		for k, v := range vars {
			if strings.EqualFold(k, want) {
				return normalizeCELValue(v), true
			}
		}
	}
	return nil, false
}

func normalizeCELValue(v interface{}) interface{} {
	switch x := v.(type) {
	case float64:
		return int64(x)
	case float32:
		return int64(x)
	case int:
		return int64(x)
	case int32:
		return int64(x)
	case int64:
		return x
	case uint32:
		return int64(x)
	case uint64:
		return int64(x)
	default:
		return fmt.Sprint(v)
	}
}
