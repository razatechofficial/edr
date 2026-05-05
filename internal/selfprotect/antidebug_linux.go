//go:build linux

package selfprotect

import (
	"fmt"
	"os"
	"strconv"
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

// AntiDebugPosture returns Linux anti-debug hardening posture for health exports.
func AntiDebugPosture() map[string]any {
	out := map[string]any{
		"tracer_attached": tracerAttached(),
		"ld_preload_set":  os.Getenv("LD_PRELOAD") != "",
		"ld_debug_set":    os.Getenv("LD_DEBUG") != "",
	}
	if b, err := isDumpableProcess(); err == nil {
		out["dumpable"] = b
	} else {
		out["dumpable_error"] = err.Error()
	}
	return out
}

func isDumpableProcess() (bool, error) {
	data, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return false, err
	}
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "Dumpable:") {
			raw := strings.TrimSpace(strings.TrimPrefix(line, "Dumpable:"))
			v, convErr := strconv.Atoi(raw)
			if convErr != nil {
				return false, convErr
			}
			return v != 0, nil
		}
	}
	return false, fmt.Errorf("Dumpable field not present in /proc/self/status")
}
