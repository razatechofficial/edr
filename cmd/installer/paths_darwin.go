//go:build darwin

package main

import "path/filepath"

func defaultPlatformPaths() installPaths {
	cfg := "/Library/Application Support/EDR/config"
	return installPaths{
		binDir:        "/usr/local/bin",
		configDir:     cfg,
		dataDir:       "/Library/Application Support/EDR",
		logDir:        "/Library/Logs/EDR",
		rulesDir:      filepath.Join(cfg, "rules"),
		quarantineDir: "/Library/Application Support/EDR/quarantine",
	}
}

func agentBinaryName() string    { return "edr-agent" }
func edrctlBinaryName() string   { return "edrctl" }
func edrAliasBinaryName() string { return "edr" }
