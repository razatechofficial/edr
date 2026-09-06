//go:build !windows

package xdrclient

import "os"

func grantUsersRead(path string) {
	if path == "" {
		return
	}
	_ = os.Chmod(path, 0o644)
}
