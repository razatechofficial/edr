package main

import (
	"fmt"
	"os"
	"os/exec"
	"runtime"
)

func requirePrivileged() error {
	switch runtime.GOOS {
	case "linux", "darwin":
		if os.Geteuid() != 0 {
			return fmt.Errorf("this command requires root; re-run with sudo")
		}
	case "windows":
		if err := exec.Command("net", "session").Run(); err != nil {
			return fmt.Errorf("this command requires Administrator; re-run from an elevated prompt")
		}
	}
	return nil
}
