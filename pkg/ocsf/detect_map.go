package ocsf

import (
	"strings"
)

// OCSFEnvelopeFromFlat builds a canonical OCSF envelope map from flat schema fields.
func OCSFEnvelopeFromFlat(in map[string]interface{}) map[string]interface{} {
	if len(in) == 0 {
		return nil
	}
	if env, ok := in["ocsf"].(map[string]interface{}); ok && len(env) > 0 {
		return cloneMap(env)
	}
	if _, ok := in["class_uid"]; ok {
		return cloneMap(in)
	}
	env := BuildDetectionEnvelope(in)
	if env == nil {
		return nil
	}
	if ts := intField(in, "timestamp"); ts != 0 {
		env["time"] = ts
	} else if ts := intField(in, "time"); ts != 0 {
		env["time"] = ts
	}
	if unmapped := buildUnmappedFromFlat(in); len(unmapped) > 0 {
		env["unmapped"] = unmapped
	}
	return env
}

// CELActivationMap returns an OCSF-root map for custom CEL rule evaluation.
func CELActivationMap(env map[string]interface{}) map[string]interface{} {
	if len(env) == 0 {
		return nil
	}
	out := cloneMap(env)
	out["ocsf"] = env
	applyCELFlatFields(out, env)
	return out
}

// SigmaEvalMap adds Sigma rule field names derived from an OCSF activation map.
func SigmaEvalMap(in map[string]interface{}) map[string]interface{} {
	if len(in) == 0 {
		return in
	}
	env := in
	if nested, ok := in["ocsf"].(map[string]interface{}); ok && len(nested) > 0 {
		env = nested
	} else if _, ok := in["class_uid"]; ok {
		env = in
	} else {
		env = OCSFEnvelopeFromFlat(in)
		if env == nil {
			return in
		}
	}
	out := CELActivationMap(env)
	mergeFlatSchemaFields(out, in)
	applySigmaAliases(out, env)
	enrichDarwinSigmaFields(out)
	return out
}

func mergeFlatSchemaFields(out, in map[string]interface{}) {
	for k, v := range in {
		if isOCSFRootKey(k) {
			continue
		}
		setIfAbsent(out, k, v)
	}
}

func isOCSFRootKey(k string) bool {
	switch strings.ToLower(k) {
	case "class_uid", "class_name", "category_uid", "category_name",
		"activity_id", "activity_name", "severity_id", "severity", "time",
		"metadata", "process", "file", "reg_key", "query", "job",
		"src_endpoint", "dst_endpoint", "user", "finding", "device", "unmapped", "ocsf":
		return true
	default:
		return false
	}
}

func applyCELFlatFields(out, env map[string]interface{}) {
	if v := intField(env, "class_uid"); v != 0 {
		out["class_uid"] = v
	}
	if v := stringField(env, "class_name"); v != "" {
		out["class_name"] = v
	}
	if v := intField(env, "activity_id"); v != 0 {
		out["activity_id"] = v
	}
	if v := intField(env, "severity_id"); v != 0 {
		out["severity_id"] = v
	}
	if v := nestedString(env, "process", "cmd_line"); v != "" {
		out["process_cmd_line"] = v
	}
	if v := nestedString(env, "process", "file", "name"); v != "" {
		out["process_file_name"] = v
	}
	if v := nestedString(env, "process", "file", "path"); v != "" {
		out["process_file_path"] = v
	}
	if v := nestedString(env, "file", "path"); v != "" {
		out["file_path_ocsf"] = v
	}
	if v := nestedString(env, "dst_endpoint", "ip"); v != "" {
		out["destination_ip"] = v
	}
	if v := nestedInt(env, "dst_endpoint", "port"); v != 0 {
		out["destination_port"] = v
	}
	if v := nestedString(env, "src_endpoint", "ip"); v != "" {
		out["source_ip_ocsf"] = v
	}
	if v := nestedString(env, "query", "hostname"); v != "" {
		out["dns_query"] = v
	}
	if v := nestedString(env, "reg_key", "path"); v != "" {
		out["registry_path"] = v
	}
	if v := nestedString(env, "reg_key", "value"); v != "" {
		out["registry_value"] = v
	}
	if v := nestedString(env, "finding", "title"); v != "" {
		out["finding_title"] = v
	}
	if unmapped, ok := env["unmapped"].(map[string]interface{}); ok {
		if v := stringField(unmapped, "policy_id"); v != "" {
			out["policy_id"] = v
		}
		if v := intField(unmapped, "check_id"); v != 0 {
			out["check_id"] = v
		}
		if v := stringField(unmapped, "finding_result", "result"); v != "" {
			out["finding_result"] = v
		}
		if v := stringField(unmapped, "endpoint_id"); v != "" {
			out["endpoint_id"] = v
		}
		if v := stringField(unmapped, "hostname"); v != "" {
			out["hostname"] = v
		}
		if v := stringField(unmapped, "os"); v != "" {
			out["os"] = v
		}
	}
	if dev, ok := env["device"].(map[string]interface{}); ok {
		if v := stringField(dev, "hostname"); v != "" {
			setIfAbsent(out, "hostname", v)
		}
		if v := stringField(dev, "uid"); v != "" {
			setIfAbsent(out, "endpoint_id", v)
		}
		if osObj, ok := dev["os"].(map[string]interface{}); ok {
			if v := stringField(osObj, "name"); v != "" {
				setIfAbsent(out, "os", v)
			}
		}
	}
	if v := stringField(out, "event_type", "type", "EventType"); v != "" {
		out["event_type"] = v
	}
}

func applySigmaAliases(out, env map[string]interface{}) {
	if v := nestedString(env, "process", "file", "path"); v != "" {
		setIfAbsent(out, "Image", v)
	}
	if v := nestedString(env, "process", "cmd_line"); v != "" {
		setIfAbsent(out, "CommandLine", v)
	}
	if v := nestedString(env, "process", "file", "name"); v != "" {
		setIfAbsent(out, "ProcessName", v)
	}
	if v := nestedString(env, "file", "path"); v != "" {
		setIfAbsent(out, "TargetFilename", v)
	}
	if v := nestedString(env, "reg_key", "path"); v != "" {
		setIfAbsent(out, "TargetObject", v)
	}
	if v := nestedString(env, "reg_key", "value"); v != "" {
		setIfAbsent(out, "Details", v)
	}
	if v := nestedString(env, "query", "hostname"); v != "" {
		setIfAbsent(out, "QueryName", v)
	}
	if v := nestedString(env, "dst_endpoint", "ip"); v != "" {
		setIfAbsent(out, "DestinationIp", v)
	}
	if v := intField(env, "dst_endpoint", "port"); v != 0 {
		setIfAbsent(out, "DestinationPort", v)
	}
	if v := nestedString(env, "src_endpoint", "ip"); v != "" {
		setIfAbsent(out, "SourceIp", v)
	}
	if v := nestedInt(env, "process", "pid"); v != 0 {
		setIfAbsent(out, "PID", v)
	}
	if v := nestedInt(env, "process", "parent_process", "pid"); v != 0 {
		setIfAbsent(out, "PPID", v)
	}
}

func nestedInt(m map[string]interface{}, path ...string) int {
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
	return intFromAny(cur)
}

func intFromAny(v any) int {
	switch x := v.(type) {
	case int:
		return x
	case int32:
		return int(x)
	case int64:
		return int(x)
	case float64:
		return int(x)
	case float32:
		return int(x)
	default:
		return intField(map[string]interface{}{"v": v}, "v")
	}
}

func buildUnmappedFromFlat(in map[string]interface{}) map[string]interface{} {
	out := map[string]interface{}{}
	copyKeys(out, in,
		"endpoint_id", "EndpointID", "hostname", "Hostname", "os", "OS",
		"policy_id", "PolicyID", "check_id", "CheckID", "result", "Result",
		"esf_type", "esf_op", "target_image", "signal_number", "signal",
		"subsystem", "category", "xpc_service", "message",
	)
	if len(out) == 0 {
		return nil
	}
	return out
}

func copyKeys(dst map[string]interface{}, src map[string]interface{}, keys ...string) {
	for _, want := range keys {
		if v := stringField(src, want); v != "" {
			dst[strings.ToLower(want)] = v
			continue
		}
		if n := intField(src, want); n != 0 {
			dst[strings.ToLower(want)] = n
		}
	}
}

func nestedString(m map[string]interface{}, path ...string) string {
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
	return strings.TrimSpace(stringify(cur))
}

func stringify(v any) string {
	if v == nil {
		return ""
	}
	switch x := v.(type) {
	case string:
		return x
	default:
		return strings.TrimSpace(stringField(map[string]interface{}{"v": v}, "v"))
	}
}

func cloneMap(in map[string]interface{}) map[string]interface{} {
	out := make(map[string]interface{}, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}
