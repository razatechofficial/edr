//go:build linux

package selfprotect

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"unsafe"

	"golang.org/x/sys/unix"
)

// ioctl numbers for ext2/ext3/ext4 file attribute manipulation.
// These match the _IOR/_IOW('f', ...) macros for 64-bit architectures.
const (
	fsIOCGetFlags  = 0x80086601
	fsIOCSetFlags  = 0x40086602
	fsImmutableFL  = 0x00000010 // FS_IMMUTABLE_FL
)

func setImmutableFlag(path string) error {
	f, err := os.OpenFile(path, os.O_RDONLY, 0)
	if err != nil {
		return fmt.Errorf("tamper: open %s: %w", path, err)
	}
	defer f.Close()

	var flags int64
	if _, _, errno := unix.Syscall(unix.SYS_IOCTL, f.Fd(),
		fsIOCGetFlags, uintptr(unsafe.Pointer(&flags))); errno != 0 {
		return fmt.Errorf("tamper: FS_IOC_GETFLAGS %s: %v", path, errno)
	}

	flags |= fsImmutableFL
	if _, _, errno := unix.Syscall(unix.SYS_IOCTL, f.Fd(),
		fsIOCSetFlags, uintptr(unsafe.Pointer(&flags))); errno != 0 {
		return fmt.Errorf("tamper: FS_IOC_SETFLAGS %s: %v", path, errno)
	}
	return nil
}

func isImmutableFlag(path string) bool {
	f, err := os.OpenFile(path, os.O_RDONLY, 0)
	if err != nil {
		return false
	}
	defer f.Close()

	var flags int64
	if _, _, errno := unix.Syscall(unix.SYS_IOCTL, f.Fd(),
		fsIOCGetFlags, uintptr(unsafe.Pointer(&flags))); errno != 0 {
		return false
	}
	return flags&fsImmutableFL != 0
}

// findTamperingProcess walks /proc/*/fd looking for an open descriptor
// pointing at the tampered path (P1-20). Returns the first matching PID
// or 0 if none. This is best-effort — by the time the fsnotify event
// fires the writer may already have closed the fd and exited. A proper
// implementation uses fanotify FAN_OPEN_PERM with FAN_REPORT_TID, but
// that requires CAP_SYS_ADMIN and a kernel hook beyond the scope of
// this fix; the /proc walk works in the common case (long-lived
// editor / persistence-script writers).
func findTamperingProcess(path string) int {
	abs, err := filepath.Abs(path)
	if err != nil {
		abs = path
	}
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return 0
	}
	self := os.Getpid()
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		if pid == self {
			continue
		}
		fdDir := "/proc/" + e.Name() + "/fd"
		fds, err := os.ReadDir(fdDir)
		if err != nil {
			continue
		}
		for _, fd := range fds {
			target, err := os.Readlink(filepath.Join(fdDir, fd.Name()))
			if err != nil {
				continue
			}
			// /proc symlinks may have " (deleted)" suffix when the
			// underlying file has been unlinked.
			target = strings.TrimSuffix(target, " (deleted)")
			if target == abs {
				return pid
			}
		}
	}
	return 0
}

// killProcess sends SIGKILL to the named PID. Returns the syscall
// error so the caller can surface it in the response event.
func killProcess(pid int) error {
	if pid <= 0 {
		return fmt.Errorf("tamper: refusing to kill invalid pid %d", pid)
	}
	if err := unix.Kill(pid, unix.SIGKILL); err != nil {
		return fmt.Errorf("tamper: kill %d: %w", pid, err)
	}
	return nil
}
