//go:build linux

package selfprotect

import (
	"fmt"
	"os"
	"strings"

	"golang.org/x/sys/unix"
)

// DetectDebugger returns true if a debugger is attached to the current
// process. On Linux it inspects /proc/self/status for a non-zero TracerPid
// and checks for debug-related environment variables.
func DetectDebugger() bool {
	if tracerAttached() {
		return true
	}
	for _, env := range []string{"LD_PRELOAD", "LD_DEBUG"} {
		if os.Getenv(env) != "" {
			return true
		}
	}
	return false
}

// ProtectProcess makes the current process non-dumpable via prctl, which
// prevents ptrace attachment by unprivileged users.
func ProtectProcess() error {
	if err := unix.Prctl(unix.PR_SET_DUMPABLE, 0, 0, 0, 0); err != nil {
		return fmt.Errorf("antidebug: PR_SET_DUMPABLE: %w", err)
	}
	return nil
}

func tracerAttached() bool {
	data, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return false
	}
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "TracerPid:") {
			val := strings.TrimSpace(strings.TrimPrefix(line, "TracerPid:"))
			return val != "0"
		}
	}
	return false
}
