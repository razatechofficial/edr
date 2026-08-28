//go:build !darwin && !windows

package main

import (
	"fmt"
	"os"
	"path/filepath"
)

const xdgAutostart = "/etc/xdg/autostart/edr-agent-ui.desktop"

func installLoginAutostart(paths installPaths) error {
	ui := filepath.Join(paths.binDir, agentUIBinaryName())
	if st, err := os.Stat(ui); err != nil || st.IsDir() {
		fmt.Println("    skip login item: edr-agent-ui not installed")
		return nil
	}
	if err := os.MkdirAll("/etc/xdg/autostart", 0755); err != nil {
		return err
	}
	body := fmt.Sprintf(`[Desktop Entry]
Type=Application
Name=EDR Agent
Comment=EDR Agent operator console
Exec=%s --tray
Icon=security-high
Terminal=false
Categories=System;Security;
X-GNOME-Autostart-enabled=true
`, ui)
	if err := os.WriteFile(xdgAutostart, []byte(body), 0644); err != nil {
		return err
	}
	fmt.Printf("    login item %s (all users)\n", xdgAutostart)
	return nil
}

func removeLoginAutostart() {
	_ = os.Remove(xdgAutostart)
}
