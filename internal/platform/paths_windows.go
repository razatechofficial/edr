//go:build windows

package platform

import (
	"os"
	"path/filepath"
)

func programData() string {
	if pd := os.Getenv("ProgramData"); pd != "" {
		return pd
	}
	return `C:\ProgramData`
}

func programFiles() string {
	if pf := os.Getenv("ProgramFiles"); pf != "" {
		return pf
	}
	return `C:\Program Files`
}

func DataDir() string {
	return filepath.Join(programData(), "EDR Agent")
}

func ConfigDir() string { return DataDir() }

func LogDir() string { return filepath.Join(DataDir(), "logs") }

func TempDir() string { return filepath.Join(DataDir(), "tmp") }

func RulesDir() string { return filepath.Join(DataDir(), "rules") }

func QuarantineDir() string { return filepath.Join(DataDir(), "quarantine") }

func PIDFile() string { return filepath.Join(DataDir(), "agent.pid") }

func DataSubdir(name string) string { return filepath.Join(DataDir(), name) }

func ControlSocket() string { return `\\.\pipe\edr-agent-control` }

// ConfigFileCandidates lists Windows config locations. Index 0 is the MSI path.
func ConfigFileCandidates() []string {
	pd := programData()
	return []string{
		filepath.Join(pd, "EDR Agent", "config.yml"),
		filepath.Join(pd, "EDR", "config", "agent.yaml"),
		filepath.Join(pd, "EDR", "config.yml"),
	}
}

func AlertFileCandidates() []string {
	pd := programData()
	return []string{
		filepath.Join(pd, "EDR Agent", "alerts.jsonl"),
		filepath.Join(pd, "EDR Agent", "logs", "alerts.jsonl"),
		filepath.Join(pd, "EDR", "logs", "alerts.jsonl"),
	}
}

// InstallDir is C:\Program Files\EDR Agent (per-machine).
func InstallDir() string {
	return filepath.Join(programFiles(), "EDR Agent")
}
