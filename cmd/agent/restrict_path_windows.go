//go:build windows

package main

import (
	"os/exec"
)

func restrictSensitivePath(path string) {
	if path == "" {
		return
	}
	cmd := exec.Command("icacls", path,
		"/inheritance:r",
		"/grant:r", "SYSTEM:F",
		"/grant:r", "Administrators:F",
	)
	hideConsole(cmd)
	cmd.Stdout = nil
	cmd.Stderr = nil
	_ = cmd.Run()
}
