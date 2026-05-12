//go:build !windows

package selfprotect

import (
	"os"
	"syscall"
)

// processAlive returns true when the given PID is currently in the process
// table. On Unix, signalling 0 is the canonical non-destructive liveness
// probe — the kernel resolves the pid and reports ESRCH if it is gone but
// does not deliver a signal.
func processAlive(pid int) bool {
	if pid <= 0 {
		return false
	}
	proc, err := os.FindProcess(pid)
	if err != nil {
		return false
	}
	return proc.Signal(syscall.Signal(0)) == nil
}
