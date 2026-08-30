package main

import (
	"os"
	"path/filepath"
	"strings"
)

// runningAttendedSetup is true for the downloadable Setup binary (.exe / .app),
// not the installed EDR Agent console.
func runningAttendedSetup() bool {
	exe, err := os.Executable()
	if err != nil {
		return false
	}
	if resolved, err := filepath.EvalSymlinks(exe); err == nil {
		exe = resolved
	}
	return attendedSetupPath(exe)
}

func attendedSetupPath(exe string) bool {
	norm := strings.ReplaceAll(exe, `\`, `/`)
	base := filepath.Base(norm)
	if strings.EqualFold(base, "EDR-Agent-Setup.exe") {
		return true
	}
	return strings.Contains(norm, "EDR-Agent-Setup.app")
}
