//go:build windows

package main

import (
	"os"
	"path/filepath"
)

func defaultPlatformPaths() installPaths {
	pf := os.Getenv("ProgramFiles")
	if pf == "" {
		pf = `C:\Program Files`
	}
	pd := os.Getenv("ProgramData")
	if pd == "" {
		pd = `C:\ProgramData`
	}
	root := filepath.Join(pd, "EDR Agent")
	return installPaths{
		binDir:        filepath.Join(pf, "EDR Agent"),
		configDir:     root,
		dataDir:       root,
		logDir:        filepath.Join(root, "logs"),
		rulesDir:      filepath.Join(root, "rules"),
		quarantineDir: filepath.Join(root, "quarantine"),
	}
}

func agentBinaryName() string    { return "edr-agent.exe" }
func edrctlBinaryName() string   { return "edrctl.exe" }
func edrAliasBinaryName() string { return "edr.exe" }
