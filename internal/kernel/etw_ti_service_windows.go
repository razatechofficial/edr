//go:build windows

package kernel

import (
	"os/exec"
)

// ensureTIPPLService attempts to bootstrap an optional helper service.
// Production PPL still requires ELAM/PPL signing; this is best-effort fallback.
func ensureTIPPLService() error {
	steps := [][]string{
		{"sc", "create", "EdrnTISvc", "binPath=", `%SystemRoot%\System32\edrn_ti.exe`, "type=", "own", "start=", "auto"},
		{"sc", "privs", "EdrnTISvc", "SeDebugPrivilege"},
		{"sc", "start", "EdrnTISvc"},
	}
	for _, argv := range steps {
		cmd := exec.Command(argv[0], argv[1:]...)
		if err := cmd.Run(); err != nil {
			return err
		}
	}
	return nil
}
