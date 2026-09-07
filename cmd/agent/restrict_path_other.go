//go:build !windows

package main

import "os"

func restrictSensitivePath(path string) {
	if path == "" {
		return
	}
	_ = os.Chmod(path, 0o600)
}

func restrictOperatorTree(dir string) {
	if dir == "" {
		return
	}
	_ = os.MkdirAll(dir, 0o755)
}

func publishOperatorStatusDirs(string) {}
