//go:build windows

package telemetryqueue

import (
	"os/exec"
	"syscall"
)

// prepareQueueDir grants SYSTEM+Administrators write. Go 0600 on an older
// segment (or icacls inheritance:r on ProgramData) left LocalSystem with
// Access Denied, which aborted ingest after a successful enroll.
func prepareQueueDir(dir string) {
	if dir == "" {
		return
	}
	cmd := exec.Command("icacls", dir,
		"/grant:r", "SYSTEM:(OI)(CI)F",
		"/grant:r", "Administrators:(OI)(CI)F",
	)
	cmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: 0x08000000}
	_ = cmd.Run()
}

func relaxQueuePath(path string) {
	if path == "" {
		return
	}
	attr := exec.Command("attrib", "-R", "-S", "-H", path)
	attr.SysProcAttr = &syscall.SysProcAttr{CreationFlags: 0x08000000}
	_ = attr.Run()
	cmd := exec.Command("icacls", path,
		"/inheritance:r",
		"/grant:r", "SYSTEM:F",
		"/grant:r", "Administrators:F",
	)
	cmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: 0x08000000}
	_ = cmd.Run()
}
