//go:build darwin

package main

import (
	"fmt"
	"os"
)

func checkRequiredHostAccess() error {
	if os.Geteuid() != 0 {
		return fmt.Errorf("EDR Agent must run as root (LaunchDaemon); grant Full Disk Access to edr-agent then start the service")
	}
	if !hasFullDiskAccess() {
		return fmt.Errorf("Full Disk Access is not granted for EDR Agent; open System Settings → Privacy & Security → Full Disk Access, enable EDR Agent, then start the service")
	}
	return nil
}

func hasFullDiskAccess() bool {
	paths := []string{
		"/Library/Application Support/com.apple.TCC/TCC.db",
		"/var/db/locationd/clients.plist",
	}
	for _, p := range paths {
		f, err := os.Open(p)
		if err == nil {
			_ = f.Close()
			return true
		}
	}
	return false
}
