//go:build windows

package collector

import (
	"os/exec"
	"strings"

	"golang.org/x/sys/windows/registry"
)

// PostureWindowsSigverifHint runs sigverif.exe detached (operator-visible); we only report launch status.
func PostureWindowsSigverifHint() map[string]any {
	cmd := exec.Command("sigverif.exe")
	if err := cmd.Start(); err != nil {
		return map[string]any{"sigverif": "start_failed", "detail": err.Error()}
	}
	_ = cmd.Process.Release()
	return map[string]any{"sigverif": "launched_gui", "note": "operator_should_complete_scan"}
}

// PostureWindowsAMSIProviders lists HKLM\SOFTWARE\Microsoft\AMSI\Providers subkeys.
func PostureWindowsAMSIProviders() map[string]any {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\AMSI\Providers`, registry.ENUMERATE_SUB_KEYS|registry.READ)
	if err != nil {
		return map[string]any{"error": err.Error()}
	}
	defer k.Close()
	names, err := k.ReadSubKeyNames(-1)
	if err != nil {
		return map[string]any{"error": err.Error()}
	}
	return map[string]any{"provider_guids": names, "count": len(names)}
}

// PostureWindowsBcdSecureBoot runs bcdedit /enum {current} (best-effort).
func PostureWindowsBcdSecureBoot() map[string]any {
	out, err := exec.Command("bcdedit", "/enum", "{current}").CombinedOutput()
	if err != nil {
		return map[string]any{"error": err.Error(), "detail": string(out)}
	}
	s := strings.ToLower(string(out))
	return map[string]any{
		"secure_boot_hint": strings.Contains(s, "secure boot"),
		"lines":            len(strings.Split(string(out), "\n")),
	}
}

// PostureWindowsDefenderExclusionCount estimates exclusion richness via PowerShell (best-effort).
func PostureWindowsDefenderExclusionCount() map[string]any {
	ps := `try { (Get-MpPreference).ExclusionPath.Count } catch { -1 }`
	out, err := exec.Command("powershell", "-NoProfile", "-Command", ps).CombinedOutput()
	if err != nil {
		return map[string]any{"error": err.Error(), "detail": strings.TrimSpace(string(out))}
	}
	return map[string]any{"exclusion_path_count_line": strings.TrimSpace(string(out))}
}

// PostureWindowsScheduledTasksCount uses schtasks query (bounded).
func PostureWindowsScheduledTasksCount() map[string]any {
	out, err := exec.Command("schtasks", "/query", "/fo", "LIST", "/v").CombinedOutput()
	if err != nil {
		return map[string]any{"error": err.Error()}
	}
	n := 0
	for _, line := range strings.Split(string(out), "\n") {
		if strings.HasPrefix(strings.ToLower(strings.TrimSpace(line)), "taskname:") {
			n++
		}
	}
	return map[string]any{"taskname_lines": n, "bytes": len(out)}
}
