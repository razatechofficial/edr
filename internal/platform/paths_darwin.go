//go:build darwin

package platform

import "path/filepath"

const (
	dataDir       = "/Library/Application Support/EDR"
	configDir     = "/Library/Application Support/EDR/config"
	logDir        = "/Library/Logs/EDR"
	tempDir       = "/tmp/edr"
	rulesDir      = "/Library/Application Support/EDR/rules"
	quarantineDir = "/Library/Application Support/EDR/quarantine"
	pidFile       = "/var/run/edr-agent.pid"
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

func ControlSocket() string { return "/var/run/edr-agent.sock" }

func ConfigFileCandidates() []string {
	return []string{
		"/Library/Application Support/EDR/config/agent.yaml",
		"/Library/Application Support/EDR/config.yml",
		"/Library/Application Support/EDR/config/config.yml",
	}
}

func AlertFileCandidates() []string {
	return []string{
		"/Library/Application Support/EDR/alerts/alerts.jsonl",
		"/Library/Logs/EDR/alerts.jsonl",
		"/Library/Application Support/EDR/alerts.jsonl",
	}
}
