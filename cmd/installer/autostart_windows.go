//go:build windows

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/windows/registry"
)

const windowsRunKey = `Software\Microsoft\Windows\CurrentVersion\Run`

func installLoginAutostart(paths installPaths) error {
	// Launcher sets Mesa env then starts the original Fyne UI.
	ui := filepath.Join(paths.binDir, "edr-console.exe")
	cmd := `"` + ui + `"`
	if !windowsInstallationIsServer() {
		cmd = `"` + ui + `" --tray`
	}
	if st, err := os.Stat(ui); err != nil || st.IsDir() {
		ui = filepath.Join(paths.binDir, agentUIBinaryName())
		cmd = `"` + ui + `"`
	}
	if st, err := os.Stat(ui); err != nil || st.IsDir() {
		fmt.Println("    skip login item: console not installed")
		return nil
	}
	k, _, err := registry.CreateKey(registry.LOCAL_MACHINE, windowsRunKey, registry.SET_VALUE)
	if err != nil {
		fmt.Printf("    warning: HKLM Run: %v\n", err)
		return nil
	}
	defer k.Close()
	if err := k.SetStringValue("EDR Agent", cmd); err != nil {
		fmt.Printf("    warning: HKLM Run: %v\n", err)
		return nil
	}
	fmt.Println("    login item HKLM\\...\\Run\\EDR Agent (all users)")
	return nil
}

func windowsInstallationIsServer() bool {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows NT\CurrentVersion`, registry.QUERY_VALUE)
	if err != nil {
		return false
	}
	defer k.Close()
	if pt, _, err := k.GetStringValue("InstallationType"); err == nil {
		switch pt {
		case "Server", "Server Core", "Nano Server":
			return true
		}
	}
	if name, _, err := k.GetStringValue("ProductName"); err == nil {
		return strings.Contains(strings.ToLower(name), "server")
	}
	return false
}

func removeLoginAutostart() {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, windowsRunKey, registry.SET_VALUE)
	if err != nil {
		return
	}
	defer k.Close()
	_ = k.DeleteValue("EDR Agent")
}
