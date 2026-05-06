//go:build windows

package kernel

import (
	"encoding/json"
	"os"
)

// Default path written by the Windows service installer when hardening is enabled.
const serviceHardeningPosturePath = `C:\ProgramData\EDR Agent\service_hardening_posture.json`

// WindowsServiceHardeningPosture reads the last service install hardening snapshot (best-effort).
func WindowsServiceHardeningPosture() map[string]any {
	b, err := os.ReadFile(serviceHardeningPosturePath)
	if err != nil {
		return map[string]any{"present": false, "reason": "not_installed_or_unreadable"}
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		return map[string]any{"present": false, "reason": "invalid_json"}
	}
	m["present"] = true
	return m
}
