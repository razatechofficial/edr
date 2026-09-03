//go:build linux

package main

func defaultPlatformPaths() installPaths {
	return installPaths{
		binDir:        "/usr/local/bin",
		configDir:     "/etc/edr-agent",
		dataDir:       "/var/lib/edr-agent",
		logDir:        "/var/log/edr-agent",
		rulesDir:      "/etc/edr-agent/rules",
		quarantineDir: "/var/lib/edr-agent/quarantine",
	}
}

func agentBinaryName() string    { return "edr-agent" }
func edrctlBinaryName() string   { return "edrctl" }
func edrAliasBinaryName() string { return "edr" }
