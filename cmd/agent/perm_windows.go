//go:build windows

package main

import (
	"fmt"
	"os"
	"os/exec"

	"golang.org/x/sys/windows/svc"
)

func checkRequiredHostAccess() error {
	isSvc, err := svc.IsWindowsService()
	if err == nil && isSvc {
		return nil
	}
	if exec.Command("net", "session").Run() != nil {
		return fmt.Errorf("EDR Agent requires Administrator privileges; re-run the installer or start the EDRAgent service")
	}
	root := WindowsDataRoot()
	if err := os.MkdirAll(root, 0o700); err != nil {
		return fmt.Errorf("cannot write %s: %w (install for all users with Administrator)", root, err)
	}
	return nil
}

func hostAccessWarning() string { return "" }
