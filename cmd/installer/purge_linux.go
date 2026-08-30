//go:build !darwin && !windows

package main

import (
	"os/exec"
	"path/filepath"
)

func extraPurgeTreesFor(p installPaths) []string {
	return []string{
		filepath.Join(p.dataDir, "bin"),
		filepath.Join(p.dataDir, "installer"),
		"/etc/xdg/autostart/edr-agent-ui.desktop",
	}
}

func stopProductProcesses() {
	_ = exec.Command("pkill", "-x", "edr-agent").Run()
}

func quitInstalledConsole() {
	_ = exec.Command("pkill", "-x", "edr-agent-ui").Run()
}

func forgetPackageReceipts() {}

func purgeUserConsoleState() {}
