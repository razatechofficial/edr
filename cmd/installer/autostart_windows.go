//go:build windows

package main

import (
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/sys/windows/registry"
)

const windowsRunKey = `Software\Microsoft\Windows\CurrentVersion\Run`

func installLoginAutostart(paths installPaths) error {
	ui := filepath.Join(paths.binDir, agentUIBinaryName())
	if st, err := os.Stat(ui); err != nil || st.IsDir() {
		fmt.Println("    skip login item: edr-agent-ui.exe not installed")
		return nil
	}
	k, _, err := registry.CreateKey(registry.LOCAL_MACHINE, windowsRunKey, registry.SET_VALUE)
	if err != nil {
		fmt.Printf("    warning: HKLM Run: %v\n", err)
		return nil
	}
	defer k.Close()
	if err := k.SetStringValue("EDR Agent", `"`+ui+`" --tray`); err != nil {
		fmt.Printf("    warning: HKLM Run: %v\n", err)
		return nil
	}
	fmt.Println("    login item HKLM\\...\\Run\\EDR Agent (all users)")
	return nil
}

func removeLoginAutostart() {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, windowsRunKey, registry.SET_VALUE)
	if err != nil {
		return
	}
	defer k.Close()
	_ = k.DeleteValue("EDR Agent")
}
