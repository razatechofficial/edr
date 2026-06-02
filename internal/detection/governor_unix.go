//go:build linux || darwin

package detection

import (
	"syscall"
	"time"
)

func cpuTime() time.Duration {
	var usage syscall.Rusage
	if err := syscall.Getrusage(syscall.RUSAGE_SELF, &usage); err != nil {
		return 0
	}
	user := time.Duration(usage.Utime.Nano())
	sys := time.Duration(usage.Stime.Nano())
	return user + sys
}
