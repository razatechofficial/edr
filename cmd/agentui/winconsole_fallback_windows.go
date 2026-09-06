//go:build windows

package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
)

func launchNativeConsoleIfNeeded() bool {
	if !windowsProductIsServer() && !windowsIsRemoteSession() {
		return false
	}
	exe, err := os.Executable()
	if err != nil {
		return false
	}
	path := filepath.Join(filepath.Dir(exe), "edr-console.exe")
	if st, err := os.Stat(path); err != nil || st.IsDir() {
		uiLog("native console missing at %s", path)
		return false
	}
	cmd := exec.Command(path)
	cmd.Dir = filepath.Dir(exe)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: false}
	if err := cmd.Start(); err != nil {
		uiLog("launch edr-console: %v", err)
		return false
	}
	uiLog("handed off to edr-console.exe pid=%d (skip Fyne on Server/RDP)", cmd.Process.Pid)
	return true
}
