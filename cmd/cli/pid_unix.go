//go:build !windows

package main

import (
	"errors"

	"golang.org/x/sys/unix"
)

func pidAlive(pid int) bool {
	if pid <= 0 {
		return false
	}
	err := unix.Kill(pid, 0)
	switch {
	case err == nil:
		return true
	case errors.Is(err, unix.EPERM):
		// Process exists but is not signalable by this user (e.g. root-owned agent, edrctl as normal user).
		return true
	case errors.Is(err, unix.ESRCH):
		return false
	default:
		return false
	}
}
