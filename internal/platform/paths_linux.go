//go:build linux

package platform

import "path/filepath"

const (
	dataDir       = "/var/lib/edr"
	configDir     = "/etc/edr"
	logDir        = "/var/log/edr"
	tempDir       = "/tmp/edr"
	rulesDir      = "/etc/edr/rules"
	quarantineDir = "/var/lib/edr/quarantine"
	pidFile       = "/var/run/edr-agent.pid"
)

// DataDir returns the default data directory on Linux.
func DataDir() string { return dataDir }

// ConfigDir returns the default configuration directory on Linux.
func ConfigDir() string { return configDir }

// LogDir returns the default log directory on Linux.
func LogDir() string { return logDir }

// TempDir returns the default temporary directory on Linux.
func TempDir() string { return tempDir }

// RulesDir returns the default rules directory on Linux.
func RulesDir() string { return rulesDir }

// QuarantineDir returns the default quarantine directory on Linux.
func QuarantineDir() string { return quarantineDir }

// PIDFile returns the default PID file path on Linux.
func PIDFile() string { return pidFile }

// DataSubdir returns a subdirectory under the data directory.
func DataSubdir(name string) string { return filepath.Join(dataDir, name) }
