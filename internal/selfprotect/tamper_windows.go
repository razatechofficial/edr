//go:build windows

package selfprotect

import (
	"fmt"

	"golang.org/x/sys/windows"
)

func setImmutableFlag(path string) error {
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return fmt.Errorf("tamper: invalid path: %w", err)
	}
	attrs, err := windows.GetFileAttributes(p)
	if err != nil {
		return fmt.Errorf("tamper: GetFileAttributes %s: %w", path, err)
	}
	return windows.SetFileAttributes(p,
		attrs|windows.FILE_ATTRIBUTE_READONLY|windows.FILE_ATTRIBUTE_SYSTEM)
}

func isImmutableFlag(path string) bool {
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return false
	}
	attrs, err := windows.GetFileAttributes(p)
	if err != nil {
		return false
	}
	return attrs&windows.FILE_ATTRIBUTE_READONLY != 0
}

// findTamperingProcess on Windows would require either a minifilter
// driver (proper solution) or RestartManager / NtQuerySystemInformation
// with SystemHandleInformation to enumerate open handles by name. The
// latter requires SeDebugPrivilege and is fragile across Windows
// versions. Return 0 here; production deployments should pair the
// detector with the EDR minifilter that exposes the IRP source PID via
// a named-pipe channel.
//
// TODO: integrate with the EDR minifilter PID-from-IRP channel when
// the minifilter ships.
func findTamperingProcess(path string) int {
	_ = path
	return 0
}

// killProcess opens the target with PROCESS_TERMINATE and exits it with
// a non-zero status so post-mortem tooling can distinguish "killed by
// EDR" from a normal exit.
func killProcess(pid int) error {
	if pid <= 0 {
		return fmt.Errorf("tamper: refusing to kill invalid pid %d", pid)
	}
	h, err := windows.OpenProcess(windows.PROCESS_TERMINATE, false, uint32(pid))
	if err != nil {
		return fmt.Errorf("tamper: OpenProcess %d: %w", pid, err)
	}
	defer windows.CloseHandle(h)
	const edrKillExitCode = 0xEDC0DE01
	if err := windows.TerminateProcess(h, edrKillExitCode); err != nil {
		return fmt.Errorf("tamper: TerminateProcess %d: %w", pid, err)
	}
	return nil
}
