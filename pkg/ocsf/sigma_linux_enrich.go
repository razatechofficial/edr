package ocsf

import (
	"path/filepath"
	"strings"
)

// enrichLinuxSigmaFields adds Linux audit/eBPF/journal aliases expected by Sigma rules.
func enrichLinuxSigmaFields(out map[string]interface{}) {
	if len(out) == 0 {
		return
	}
	osName := strings.ToLower(stringField(out, "os", "OS"))
	hasLinuxPath := strings.HasPrefix(stringField(out, "Image", "process_path", "path", "TargetFilename"), "/")
	if osName != "linux" && !hasLinuxPath {
		return
	}

	if img := stringField(out, "Image", "process_path", "ProcessPath"); img != "" {
		setIfAbsent(out, "Image", filepath.Clean(img))
	}
	if parent := stringField(out, "ParentImage", "parent_process_path", "parent_path"); parent != "" {
		setIfAbsent(out, "ParentImage", filepath.Clean(parent))
	}
	if path := stringField(out, "TargetFilename", "path", "file_path"); path != "" {
		setIfAbsent(out, "TargetFilename", filepath.Clean(path))
	}
	if user := stringField(out, "User", "user", "username"); user != "" {
		setIfAbsent(out, "User", user)
	}
	if op := stringField(out, "operation", "Operation", "syscall", "event.action"); op != "" {
		setIfAbsent(out, "event.action", op)
	}
	if sha := stringField(out, "image_sha256", "ImageSHA256", "hash"); sha != "" {
		setIfAbsent(out, "Hashes", "SHA256="+strings.ToUpper(sha))
	}
	if svc := stringField(out, "unit", "systemd_unit"); svc != "" {
		setIfAbsent(out, "logsource.service", "systemd")
		setIfAbsent(out, "service", svc)
	}
}
