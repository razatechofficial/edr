//go:build windows

package main

import (
	"os"
	"path/filepath"
)

func extraPurgeTreesFor(p installPaths) []string {
	pd := os.Getenv("ProgramData")
	if pd == "" {
		pd = `C:\ProgramData`
	}
	return []string{
		p.binDir,
		filepath.Join(pd, "EDR", "setup"),
		filepath.Join(pd, "EDR"),
	}
}

func stopProductProcesses() {
	_ = runCmd("taskkill", "/F", "/IM", "edr-agent.exe")
}

func quitInstalledConsole() {
	// Setup is EDR-Agent-Setup.exe — do not kill it.
	_ = runCmd("taskkill", "/F", "/IM", "edr-agent-ui.exe")
}

func forgetPackageReceipts() {}

func purgeUserConsoleState() {}
