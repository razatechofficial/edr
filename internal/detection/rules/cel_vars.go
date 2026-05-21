package rules

import (
	"fmt"
	"strings"

	"github.com/google/cel-go/cel"
)

// celVarNames lists CEL activation keys in declaration order.
var celVarNames = []string{
	"event_type",
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
	// OCSF-native aliases (underscore form; populated from EnrichDetectionMap keys).
	"process_file_name",
	"process_file_path",
	"process_cmd_line",
	"file_path_ocsf",
	"registry_path",
	"registry_value",
	"destination_ip",
	"destination_port",
	"source_ip_ocsf",
	"dns_query",
	"ocsf_class_uid",
	"ocsf_class_name",
}

func newCELEnv() (*cel.Env, error) {
	opts := make([]cel.EnvOption, 0, len(celVarNames))
	for _, name := range celVarNames {
		switch name {
		case "pid", "ppid", "source_port", "dest_port", "destination_port", "ocsf_class_uid":
			opts = append(opts, cel.Variable(name, cel.IntType))
		default:
			opts = append(opts, cel.Variable(name, cel.StringType))
		}
	}
	return cel.NewEnv(opts...)
}

func activationFromMap(vars map[string]interface{}) map[string]interface{} {
	out := make(map[string]interface{}, len(celVarNames)+8)
	for _, name := range celVarNames {
		switch name {
		case "pid", "ppid", "source_port", "dest_port", "destination_port", "ocsf_class_uid":
			out[name] = int64(0)
		default:
			out[name] = ""
		}
	}

	alias := map[string][]string{
		"process_name":      {"process_name", "ProcessName", "process.file.name", "ocsf.process.file.name"},
		"process_path":      {"process_path", "ProcessPath", "Image", "process.file.path", "ocsf.process.file.path", "process.executable"},
		"command_line":      {"command_line", "CommandLine", "process.command_line", "ocsf.process.cmd_line"},
		"parent_name":       {"parent_name", "ParentName", "ParentImage", "process.parent.name"},
		"file_path":         {"file_path", "path", "Path", "TargetFilename"},
		"file_path_ocsf":    {"file.path", "ocsf.file.path", "file_path", "path", "TargetFilename"},
		"file_operation":    {"file_operation", "operation", "Operation", "file.action"},
		"dest_ip":           {"dest_ip", "DstIP", "DestinationIp", "destination.ip", "ocsf.dst_endpoint.ip"},
		"destination_ip":    {"destination_ip", "dest_ip", "DestinationIp", "destination.ip"},
		"dest_port":           {"dest_port", "DstPort", "DestinationPort", "destination.port"},
		"destination_port":    {"destination_port", "dest_port", "DestinationPort", "destination.port"},
		"source_ip":           {"source_ip", "SrcIP", "SourceIp", "source.ip"},
		"source_ip_ocsf":      {"source_ip_ocsf", "source_ip", "SourceIp", "ocsf.src_endpoint.ip"},
		"domain":              {"domain", "Domain", "QueryName", "dns.question.name"},
		"dns_query":             {"dns_query", "domain", "QueryName", "dns.question.name"},
		"registry_path":         {"registry_path", "RegistryPath", "TargetObject", "registry.path"},
		"registry_value":        {"registry_value", "RegistryValue", "Details", "registry.value"},
		"process_file_name":     {"process_file_name", "process_name", "process.file.name"},
		"process_file_path":     {"process_file_path", "process_path", "process.file.path", "Image"},
		"process_cmd_line":      {"process_cmd_line", "command_line", "process.command_line"},
		"ocsf_class_name":       {"ocsf_class_name", "ocsf.class_name"},
		"ocsf_class_uid":        {"ocsf_class_uid", "ocsf.class_uid"},
		"event_type":            {"event_type", "type", "EventType"},
		"hostname":              {"hostname", "Hostname"},
		"os":                    {"os", "OS"},
		"user":                  {"user", "User"},
		"protocol":              {"protocol", "Protocol", "network.transport"},
		"auth_type":             {"auth_type", "AuthType"},
		"auth_outcome":          {"auth_outcome", "AuthOutcome", "outcome"},
		"severity":              {"severity", "Severity"},
		"file_hash":             {"file_hash", "FileHash", "hash", "Hashes"},
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
