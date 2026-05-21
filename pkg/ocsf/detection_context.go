package ocsf

import (
	"path/filepath"
	"strings"
)

// BuildDetectionEnvelope constructs a nested OCSF-shaped map for CEL and export.
// Flat legacy and ECS aliases remain on the outer map via EnrichDetectionMap.
func BuildDetectionEnvelope(in map[string]interface{}) map[string]interface{} {
	if len(in) == 0 {
		return nil
	}
	eventType := strings.ToLower(stringField(in, "event_type", "type"))
	classUID := classUIDForEventType(eventType)
	className := classNameForEventType(eventType)

	env := map[string]interface{}{
		"class_uid":  classUID,
		"class_name": className,
		"metadata": map[string]interface{}{
			"version": SchemaVersion,
		},
	}
	if classUID == 0 {
		delete(env, "class_uid")
	}
	if className == "" {
		delete(env, "class_name")
	}

	if proc := buildProcessObject(in); len(proc) > 0 {
		env["process"] = proc
	}
	if file := buildFileObject(in); len(file) > 0 {
		env["file"] = file
	}
	if dst := buildEndpointObject(in, "dest_ip", "DstIP", "DestinationIp", "destination.ip"); len(dst) > 0 {
		env["dst_endpoint"] = dst
	}
	if src := buildEndpointObject(in, "src_ip", "SrcIP", "SourceIp", "source.ip"); len(src) > 0 {
		env["src_endpoint"] = src
	}
	if dev := buildDeviceObject(in); len(dev) > 0 {
		env["device"] = dev
	}

	return env
}

func buildProcessObject(in map[string]interface{}) map[string]interface{} {
	name := stringField(in, "process_name", "ProcessName")
	path := stringField(in, "process_path", "ProcessPath", "Image")
	cmd := stringField(in, "command_line", "CommandLine")
	user := stringField(in, "user", "User")
	pid := intField(in, "pid", "PID")
	ppid := intField(in, "ppid", "PPID")
	parent := stringField(in, "parent_name", "ParentName", "ParentImage")

	if name == "" && path == "" && cmd == "" && pid == 0 && ppid == 0 && user == "" && parent == "" {
		return nil
	}

	out := map[string]interface{}{}
	if name != "" || path != "" {
		fileObj := map[string]interface{}{}
		if name != "" {
			fileObj["name"] = name
		}
		if path != "" {
			fileObj["path"] = path
		}
		out["file"] = fileObj
	}
	if cmd != "" {
		out["cmd_line"] = cmd
	}
	if pid != 0 {
		out["pid"] = pid
	}
	if ppid != 0 {
		out["parent_process"] = map[string]interface{}{"pid": ppid}
	}
	if parent != "" {
		if pp, ok := out["parent_process"].(map[string]interface{}); ok {
			pp["file"] = map[string]interface{}{"name": parent}
		} else {
			out["parent_process"] = map[string]interface{}{
				"file": map[string]interface{}{"name": parent},
			}
		}
	}
	if user != "" {
		out["user"] = map[string]interface{}{"name": user}
	}
	return out
}

func buildFileObject(in map[string]interface{}) map[string]interface{} {
	path := stringField(in, "path", "Path", "file_path", "TargetFilename")
	op := stringField(in, "operation", "Operation", "file_operation")
	if path == "" && op == "" {
		return nil
	}
	out := map[string]interface{}{}
	if path != "" {
		out["path"] = path
		out["name"] = filepath.Base(path)
	}
	if op != "" {
		out["activity_name"] = op
	}
	return out
}

func buildEndpointObject(in map[string]interface{}, keys ...string) map[string]interface{} {
	ip := stringField(in, keys...)
	port := intField(in, "dest_port", "DstPort", "DestinationPort", "destination.port")
	if ip == "" && port == 0 {
		return nil
	}
	out := map[string]interface{}{}
	if ip != "" {
		out["ip"] = ip
	}
	if port != 0 {
		out["port"] = port
	}
	return out
}

func buildDeviceObject(in map[string]interface{}) map[string]interface{} {
	host := stringField(in, "hostname", "Hostname")
	ep := stringField(in, "endpoint_id", "EndpointID")
	osName := stringField(in, "os", "OS")
	if host == "" && ep == "" && osName == "" {
		return nil
	}
	out := map[string]interface{}{}
	if host != "" {
		out["hostname"] = host
	}
	if ep != "" {
		out["uid"] = ep
	}
	if osName != "" {
		out["os"] = map[string]interface{}{"name": osName}
	}
	return out
}

// applyCanonicalOCSFFields sets primary OCSF CEL flat fields on the detection map.
func applyCanonicalOCSFFields(out map[string]interface{}) {
	eventType := strings.ToLower(stringField(out, "event_type", "type"))
	if uid := classUIDForEventType(eventType); uid != 0 {
		setIfAbsent(out, "class_uid", uid)
		setIfAbsent(out, "ocsf.class_uid", uid)
		setIfAbsent(out, "ocsf_class_uid", uid)
	}
	if name := classNameForEventType(eventType); name != "" {
		setIfAbsent(out, "class_name", name)
		setIfAbsent(out, "ocsf.class_name", name)
		setIfAbsent(out, "ocsf_class_name", name)
	}

	if v := stringField(out, "process_name", "ProcessName", "process.file.name"); v != "" {
		setIfAbsent(out, "process_file_name", v)
	}
	if v := stringField(out, "process_path", "ProcessPath", "Image", "process.file.path"); v != "" {
		setIfAbsent(out, "process_file_path", v)
	}
	if v := stringField(out, "command_line", "CommandLine", "process.command_line", "ocsf.process.cmd_line"); v != "" {
		setIfAbsent(out, "process_cmd_line", v)
	}
	if v := stringField(out, "path", "Path", "file_path", "file.path", "ocsf.file.path"); v != "" {
		setIfAbsent(out, "file_path_ocsf", v)
	}
}
