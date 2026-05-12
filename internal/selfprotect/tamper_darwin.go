//go:build darwin

package selfprotect

import (
	"fmt"

	"golang.org/x/sys/unix"
)

func setImmutableFlag(path string) error {
	var st unix.Stat_t
	if err := unix.Lstat(path, &st); err != nil {
		return fmt.Errorf("tamper: lstat %s: %w", path, err)
	}
	newFlags := st.Flags | unix.SF_IMMUTABLE
	if err := unix.Chflags(path, int(newFlags)); err != nil {
		return fmt.Errorf("tamper: chflags %s: %w", path, err)
	}
	return nil
}

func isImmutableFlag(path string) bool {
	var st unix.Stat_t
	if err := unix.Lstat(path, &st); err != nil {
		return false
	}
	return st.Flags&(unix.SF_IMMUTABLE|unix.UF_IMMUTABLE) != 0
}

// findTamperingProcess on macOS would ideally subscribe to ESF
// NOTIFY_WRITE / AUTH_WRITE for the protected path and pull the audit
// token from the message. That integration lives in the ESF driver and
// is wired separately; the watchdog cannot peek into ESF's queue from
// here. Return 0 as a signal for the caller to emit a detection
// without an attribution.
//
// TODO: route ESF NOTIFY_WRITE events for protected paths back into the
// tamper detector via an in-process channel so we can attribute the
// writer PID without spawning another ESF client.
func findTamperingProcess(path string) int {
	_ = path
	return 0
}

// killProcess sends SIGKILL on macOS via the standard POSIX kill(2).
func killProcess(pid int) error {
	if pid <= 0 {
		return fmt.Errorf("tamper: refusing to kill invalid pid %d", pid)
	}
	if err := unix.Kill(pid, unix.SIGKILL); err != nil {
		return fmt.Errorf("tamper: kill %d: %w", pid, err)
	}
	return nil
}
