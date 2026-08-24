//go:build linux

package platform

import "path/filepath"

const (
	dataDir       = "/var/lib/edr-agent"
	configDir     = "/etc/edr-agent"
	logDir        = "/var/log/edr-agent"
	tempDir       = "/tmp/edr-agent"
	rulesDir      = "/etc/edr-agent/rules"
	quarantineDir = "/var/lib/edr-agent/quarantine"
	pidFile       = "/run/edr-agent.pid"
)

func DataDir() string       { return dataDir }
func ConfigDir() string     { return configDir }
func LogDir() string        { return logDir }
func TempDir() string       { return tempDir }
func RulesDir() string      { return rulesDir }
func QuarantineDir() string { return quarantineDir }
func PIDFile() string       { return pidFile }
func DataSubdir(name string) string {
	return filepath.Join(dataDir, name)
}

func ControlSocket() string { return "/run/edr-agent.sock" }

func ConfigFileCandidates() []string {
	return []string{
		"/etc/edr-agent/config.yml",
		"/etc/edr-agent/agent.yaml",
		"/etc/edr/agent.yaml",
		"/etc/edr/config.yml",
	}
}

func AlertFileCandidates() []string {
	return []string{
		"/var/lib/edr-agent/alerts.jsonl",
		"/var/log/edr-agent/alerts.jsonl",
		"/var/log/edr/alerts.jsonl",
	}
}
