//go:build linux || darwin

package platform

import (
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

// IsRoot reports whether the process is running as root (UID 0).
func IsRoot() bool {
	return os.Getuid() == 0
}

// RequireRoot returns an error if the process is not running as root.
func RequireRoot() error {
	if !IsRoot() {
		return fmt.Errorf("this operation requires root privileges (current uid=%d)", os.Getuid())
	}
	return nil
}

// DropPrivileges sets the process effective and real GID and UID to the
// specified values. This is typically used to drop from root to an
// unprivileged service account after binding privileged resources.
func DropPrivileges(uid, gid int) error {
	if err := unix.Setgid(gid); err != nil {
		return fmt.Errorf("setgid(%d): %w", gid, err)
	}
	if err := unix.Setuid(uid); err != nil {
		return fmt.Errorf("setuid(%d): %w", uid, err)
	}
	return nil
}
