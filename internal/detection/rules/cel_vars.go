package rules

import (
	"fmt"
	"strings"

	"github.com/google/cel-go/cel"
)

// celVarNames lists CEL activation keys backed by OCSF 1.3 attributes.
var celVarNames = []string{
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
	"finding_title",
	"policy_id",
	"check_id",
	"finding_result",
	"activity_id",
	"severity_id",
	"event_type",
	"endpoint_id",
	"hostname",
	"os",
}

func newCELEnv() (*cel.Env, error) {
	opts := make([]cel.EnvOption, 0, len(celVarNames)+1)
	for _, name := range celVarNames {
		switch name {
		case "class_uid", "check_id", "activity_id", "severity_id", "destination_port":
			opts = append(opts, cel.Variable(name, cel.IntType))
		default:
			opts = append(opts, cel.Variable(name, cel.StringType))
		}
	}
	opts = append(opts, cel.Variable("ocsf", cel.DynType))
	return cel.NewEnv(opts...)
}

func activationFromMap(vars map[string]interface{}) map[string]interface{} {
	if len(vars) == 0 {
		return map[string]interface{}{"ocsf": map[string]interface{}{}}
	}
	env := vars
	if nested, ok := vars["ocsf"].(map[string]interface{}); ok && len(nested) > 0 {
		env = nested
	}
	out := make(map[string]interface{}, len(celVarNames)+8)
	for _, name := range celVarNames {
		switch name {
		case "class_uid", "check_id", "activity_id", "severity_id", "destination_port":
			out[name] = int64(0)
		default:
			out[name] = ""
		}
	}
	for _, name := range celVarNames {
		if v, ok := vars[name]; ok {
			out[name] = normalizeCELValue(v)
		}
	}
	if v, ok := env["class_uid"]; ok {
		out["class_uid"] = normalizeCELValue(v)
	}
	if v, ok := env["class_name"]; ok {
		out["class_name"] = normalizeCELValue(v)
	}
	if v, ok := env["activity_id"]; ok {
		out["activity_id"] = normalizeCELValue(v)
	}
	if v, ok := env["severity_id"]; ok {
		out["severity_id"] = normalizeCELValue(v)
	}
	if v := nestedStringCEL(env, "process", "cmd_line"); v != "" {
		out["process_cmd_line"] = v
	}
	if v := nestedStringCEL(env, "process", "file", "name"); v != "" {
		out["process_file_name"] = v
	}
	if v := nestedStringCEL(env, "process", "file", "path"); v != "" {
		out["process_file_path"] = v
	}
	if v := nestedStringCEL(env, "file", "path"); v != "" {
		out["file_path_ocsf"] = v
	}
	if v := nestedStringCEL(env, "dst_endpoint", "ip"); v != "" {
		out["destination_ip"] = v
	}
	if v := nestedIntCEL(env, "dst_endpoint", "port"); v != 0 {
		out["destination_port"] = int64(v)
	}
	if v := nestedStringCEL(env, "src_endpoint", "ip"); v != "" {
		out["source_ip_ocsf"] = v
	}
	if v := nestedStringCEL(env, "query", "hostname"); v != "" {
		out["dns_query"] = v
	}
	if v := nestedStringCEL(env, "reg_key", "path"); v != "" {
		out["registry_path"] = v
	}
	if v := nestedStringCEL(env, "reg_key", "value"); v != "" {
		out["registry_value"] = v
	}
	if v := nestedStringCEL(env, "finding", "title"); v != "" {
		out["finding_title"] = v
	}
	if unmapped, ok := env["unmapped"].(map[string]interface{}); ok {
		if v := stringFieldCEL(unmapped, "policy_id"); v != "" {
			out["policy_id"] = v
		}
		if v := intFieldCEL(unmapped, "check_id"); v != 0 {
			out["check_id"] = int64(v)
		}
		if v := stringFieldCEL(unmapped, "finding_result", "result"); v != "" {
			out["finding_result"] = v
		}
		if v := stringFieldCEL(unmapped, "endpoint_id"); v != "" {
			out["endpoint_id"] = v
		}
		if v := stringFieldCEL(unmapped, "hostname"); v != "" {
			out["hostname"] = v
		}
		if v := stringFieldCEL(unmapped, "os"); v != "" {
			out["os"] = v
		}
	}
	if v := stringFieldCEL(vars, "event_type", "type", "EventType"); v != "" {
		out["event_type"] = v
	}
	out["ocsf"] = env
	return out
}

func nestedStringCEL(m map[string]interface{}, path ...string) string {
	cur := any(m)
	for _, key := range path {
		obj, ok := cur.(map[string]interface{})
		if !ok {
			return ""
		}
		cur, ok = obj[key]
		if !ok {
			return ""
		}
	}
	return strings.TrimSpace(fmt.Sprint(cur))
}

func nestedIntCEL(m map[string]interface{}, path ...string) int {
	cur := any(m)
	for _, key := range path {
		obj, ok := cur.(map[string]interface{})
		if !ok {
			return 0
		}
		cur, ok = obj[key]
		if !ok {
			return 0
		}
	}
	switch x := cur.(type) {
	case int:
		return x
	case int64:
		return int(x)
	case float64:
		return int(x)
	default:
		return intFieldCEL(map[string]interface{}{"v": cur}, "v")
	}
}

func stringFieldCEL(m map[string]interface{}, keys ...string) string {
	for _, want := range keys {
		for k, v := range m {
			if strings.EqualFold(k, want) {
				return strings.TrimSpace(fmt.Sprint(v))
			}
		}
	}
	return ""
}

func intFieldCEL(m map[string]interface{}, keys ...string) int {
	s := stringFieldCEL(m, keys...)
	if s == "" {
		return 0
	}
	var n int
	_, _ = fmt.Sscanf(s, "%d", &n)
	return n
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
