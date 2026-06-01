//go:build windows

package main

import (
	"os"
	"path/filepath"
)

const (
	windowsInstallDirName = "EDR Agent"
	windowsDataDirName    = "EDR Agent"
	windowsServiceName    = "EDRAgent"
)

// WindowsInstallDir is the per-machine agent binary directory (CrowdStrike-style layout).
func WindowsInstallDir() string {
	return filepath.Join(os.Getenv("ProgramFiles"), windowsInstallDirName)
}

// WindowsDataRoot holds config, rules, telemetry state, and runtime data.
func WindowsDataRoot() string {
	if pd := os.Getenv("ProgramData"); pd != "" {
		return filepath.Join(pd, windowsDataDirName)
	}
	return `C:\ProgramData\` + windowsDataDirName
}

// WindowsConfigPath is the default sensor configuration file.
func WindowsConfigPath() string {
	return filepath.Join(WindowsDataRoot(), "config.yml")
}

// WindowsControlPlaneIntentPath records optional kernel control-plane intent.
func WindowsControlPlaneIntentPath() string {
	return filepath.Join(WindowsDataRoot(), "control_plane.intent")
}

func windowsConfigFromArgs() string {
	for i := 1; i < len(os.Args)-1; i++ {
		if os.Args[i] == "--config" {
			if p := os.Args[i+1]; p != "" {
				return p
			}
		}
	}
	return WindowsConfigPath()
}
