//go:build windows

package platform

import (
	"fmt"

	"golang.org/x/sys/windows"
)

// IsRoot reports whether the process is running with administrator privileges.
func IsRoot() bool {
	return windows.GetCurrentProcessToken().IsElevated()
}

// RequireRoot returns an error if the process is not running as administrator.
func RequireRoot() error {
	if !IsRoot() {
		return fmt.Errorf("this operation requires administrator privileges")
	}
	return nil
}

// DropPrivileges is not supported on Windows. Windows does not use POSIX-style
// UID/GID privilege dropping; process tokens are managed via the Windows API.
func DropPrivileges(_, _ int) error {
	return fmt.Errorf("DropPrivileges is not supported on Windows")
}
