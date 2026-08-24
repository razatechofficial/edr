//go:build !windows

package main

import "os"

func restrictSensitivePath(path string) {
	if path == "" {
		return
	}
	_ = os.Chmod(path, 0o600)
}
