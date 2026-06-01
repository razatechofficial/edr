package ocsf

import (
	"path/filepath"
	"strings"
)

// enrichWindowsSigmaFields adds Windows ETW/registry/process aliases expected by Sigma rules.
func enrichWindowsSigmaFields(out map[string]interface{}) {
	if len(out) == 0 {
		return
	}
	osName := strings.ToLower(stringField(out, "os", "OS"))
	imgHint := stringField(out, "Image", "process_path", "path", "TargetObject", "key_path")
	hasWinPath := strings.Contains(imgHint, `\`) || strings.Contains(imgHint, ":\\")
	if osName != "windows" && !hasWinPath {
		return
	}

	normalizeWinPath := func(p string) string {
		p = strings.TrimSpace(p)
		if p == "" {
			return ""
		}
		return filepath.FromSlash(strings.ReplaceAll(p, "/", `\`))
	}

	if img := stringField(out, "Image", "process_path", "ProcessPath"); img != "" {
		setIfAbsent(out, "Image", normalizeWinPath(img))
	}
	if parent := stringField(out, "ParentImage", "parent_process_path", "parent_path"); parent != "" {
		setIfAbsent(out, "ParentImage", normalizeWinPath(parent))
	}
	if key := stringField(out, "TargetObject", "key_path", "registry_path", "RegistryPath"); key != "" {
		setIfAbsent(out, "TargetObject", normalizeWinPath(key))
	}
	if val := stringField(out, "Details", "new_data", "registry_value", "RegistryValue"); val != "" {
		setIfAbsent(out, "Details", val)
	}
	if user := stringField(out, "User", "user", "username"); user != "" {
		setIfAbsent(out, "User", user)
	}
	if sha := stringField(out, "image_sha256", "ImageSHA256", "hash"); sha != "" {
		setIfAbsent(out, "Hashes", "SHA256="+strings.ToUpper(sha))
	}
	if tgt := stringField(out, "target_image", "TargetImage"); tgt != "" {
		setIfAbsent(out, "TargetImage", normalizeWinPath(tgt))
	}
	if src := stringField(out, "source_image", "SourceImage"); src != "" {
		setIfAbsent(out, "SourceImage", normalizeWinPath(src))
	}
	if op := stringField(out, "operation", "Operation", "event_type", "EventType"); op != "" {
		setIfAbsent(out, "EventType", op)
	}
}
