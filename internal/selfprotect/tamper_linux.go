//go:build linux

package selfprotect

import (
	"fmt"
	"os"
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
