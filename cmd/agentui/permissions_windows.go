//go:build windows

package main

import "os/exec"

func needsFullDiskAccess() bool { return false }

func hasFullDiskAccess() bool { return true }

func openOSGrantSettings() error {
	_ = exec.Command("cmd", "/c", "start", "", "windowsdefender:").Start()
	_ = exec.Command("cmd", "/c", "start", "", "ms-settings:windowsdefender").Start()
	return exec.Command("control", "firewall.cpl").Start()
}
