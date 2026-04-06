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

// DataDir returns the default data directory on macOS.
func DataDir() string { return dataDir }

// ConfigDir returns the default configuration directory on macOS.
func ConfigDir() string { return configDir }

// LogDir returns the default log directory on macOS.
func LogDir() string { return logDir }

// TempDir returns the default temporary directory on macOS.
func TempDir() string { return tempDir }

// RulesDir returns the default rules directory on macOS.
func RulesDir() string { return rulesDir }

// QuarantineDir returns the default quarantine directory on macOS.
func QuarantineDir() string { return quarantineDir }

// PIDFile returns the default PID file path on macOS.
func PIDFile() string { return pidFile }

// DataSubdir returns a subdirectory under the data directory.
func DataSubdir(name string) string { return filepath.Join(dataDir, name) }
