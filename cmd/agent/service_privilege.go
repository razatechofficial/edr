package main

import (
	"fmt"
	"os"
	"runtime"
)

// requireServicePrivilege refuses an install or uninstall that cannot succeed.
//
// Both operations write to directories only root or an Administrator can touch
// — /etc/systemd/system, /Library/LaunchDaemons, the service control manager.
// Checking first turns a confusing partial failure into one sentence naming
// what is needed. Uninstall in particular used to run without any check and
// report success regardless, so an operator without privilege was told the
// sensor was gone while it kept running.
func requireServicePrivilege(action string) error {
	if runtime.GOOS == "windows" {
		// Windows elevation is checked by the caller that talks to the service
		// control manager; a token check here would duplicate it and the SCM
		// gives the better error.
		return nil
	}
	if os.Geteuid() == 0 {
		return nil
	}
	return fmt.Errorf("%s requires root: re-run with sudo", action)
}
