//go:build darwin

package selfprotect

import (
	"fmt"

	"golang.org/x/sys/unix"
)

func setImmutableFlag(path string) error {
	var st unix.Stat_t
	if err := unix.Lstat(path, &st); err != nil {
		return fmt.Errorf("tamper: lstat %s: %w", path, err)
	}
	newFlags := st.Flags | unix.SF_IMMUTABLE
	if err := unix.Chflags(path, int(newFlags)); err != nil {
		return fmt.Errorf("tamper: chflags %s: %w", path, err)
	}
	return nil
}

func isImmutableFlag(path string) bool {
	var st unix.Stat_t
	if err := unix.Lstat(path, &st); err != nil {
		return false
	}
	return st.Flags&(unix.SF_IMMUTABLE|unix.UF_IMMUTABLE) != 0
}
