//go:build windows

package platform

import "path/filepath"

const (
	dataDir       = `C:\ProgramData\EDR`
	configDir     = `C:\ProgramData\EDR\config`
	logDir        = `C:\ProgramData\EDR\logs`
	tempDir       = `C:\ProgramData\EDR\temp`
	rulesDir      = `C:\ProgramData\EDR\rules`
	quarantineDir = `C:\ProgramData\EDR\quarantine`
	pidFile       = `C:\ProgramData\EDR\edr-agent.pid`
)

// DataDir returns the default data directory on Windows.
func DataDir() string { return dataDir }

// ConfigDir returns the default configuration directory on Windows.
func ConfigDir() string { return configDir }

// LogDir returns the default log directory on Windows.
func LogDir() string { return logDir }

// TempDir returns the default temporary directory on Windows.
func TempDir() string { return tempDir }

// RulesDir returns the default rules directory on Windows.
func RulesDir() string { return rulesDir }

// QuarantineDir returns the default quarantine directory on Windows.
func QuarantineDir() string { return quarantineDir }

// PIDFile returns the default PID file path on Windows.
func PIDFile() string { return pidFile }

// DataSubdir returns a subdirectory under the data directory.
func DataSubdir(name string) string { return filepath.Join(dataDir, name) }
