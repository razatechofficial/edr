//go:build windows

package xdrclient

import (
	"os/exec"
	"syscall"
)

// grantUsersRead lets the unelevated console read a status sidecar. xdr-tls
// is SYSTEM+Administrators only after MSI hardening, so ingest.status there
// is invisible to edrctl ui and the dashboard stays on Retrying.
func grantUsersRead(path string) {
	if path == "" {
		return
	}
	cmd := exec.Command("icacls", path,
		"/grant", "*S-1-5-32-545:R",
		"/grant", "SYSTEM:F",
		"/grant", "Administrators:F",
	)
	cmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: 0x08000000}
	_ = cmd.Run()
}
