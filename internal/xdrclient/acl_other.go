//go:build !windows

package xdrclient

import "os"

func clearFileWriteBarrier(path string) {}

func grantUsersRead(path string) {
	if path == "" {
		return
	}
	_ = os.Chmod(path, 0o644)
}
