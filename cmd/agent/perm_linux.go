//go:build linux

package main

import (
	"fmt"
	"os"
)

func checkRequiredHostAccess() error {
	if os.Geteuid() != 0 {
		return fmt.Errorf("EDR Agent must run as root (systemd service)")
	}
	return nil
}

func hostAccessWarning() string { return "" }
