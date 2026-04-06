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
