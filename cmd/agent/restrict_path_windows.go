//go:build windows

package main

import (
	"os"
	"os/exec"
)

func restrictSensitivePath(path string) {
	if path == "" {
		return
	}
	st, err := os.Stat(path)
	sys, adm := "SYSTEM:F", "Administrators:F"
	if err == nil && st.IsDir() {
		sys, adm = "SYSTEM:(OI)(CI)F", "Administrators:(OI)(CI)F"
	}
	cmd := exec.Command("icacls", path,
		"/inheritance:r",
		"/grant:r", sys,
		"/grant:r", adm,
	)
	hideConsole(cmd)
	cmd.Stdout = nil
	cmd.Stderr = nil
	_ = cmd.Run()
}
