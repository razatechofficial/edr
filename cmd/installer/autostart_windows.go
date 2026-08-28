//go:build windows

package main

import (
	"fmt"
	"os"
	"path/filepath"
)

func installLoginAutostart(paths installPaths) error {
	ui := filepath.Join(paths.binDir, agentUIBinaryName())
	if st, err := os.Stat(ui); err != nil || st.IsDir() {
		fmt.Println("    skip login item: edr-agent-ui.exe not installed")
		return nil
	}
	quoted := `"` + ui + `" --tray`
	if err := runCmd("reg", "add", `HKLM\Software\Microsoft\Windows\CurrentVersion\Run`,
		"/v", "EDR Agent", "/t", "REG_SZ", "/d", quoted, "/f"); err != nil {
		fmt.Printf("    warning: HKLM Run: %v\n", err)
		return nil
	}
	fmt.Println("    login item HKLM\\...\\Run\\EDR Agent (all users)")
	return nil
}

func removeLoginAutostart() {
	_ = runCmd("reg", "delete", `HKLM\Software\Microsoft\Windows\CurrentVersion\Run`, "/v", "EDR Agent", "/f")
}
