//go:build windows

package detection

import (
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

func cpuTime() time.Duration {
	h, err := windows.GetCurrentProcess()
	if err != nil {
		return 0
	}
	var creation, exit, kernel, user windows.Filetime
	if err := windows.GetProcessTimes(h, &creation, &exit, &kernel, &user); err != nil {
		return 0
	}
	k := filetimeToDuration(kernel)
	u := filetimeToDuration(user)
	return k + u
}

func filetimeToDuration(ft windows.Filetime) time.Duration {
	ns := *(*int64)(unsafe.Pointer(&ft)) * 100
	return time.Duration(ns)
}
