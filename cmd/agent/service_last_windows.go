//go:build windows

package main

import (
	"os"
	"path/filepath"
)

func writeServiceLastError(err error) {
	root := WindowsDataRoot()
	dir := filepath.Join(root, "logs")
	_ = os.MkdirAll(dir, 0o755)
	msg := "OK\n"
	if err != nil {
		msg = err.Error() + "\n"
	}
	_ = os.WriteFile(filepath.Join(dir, "service.last"), []byte(msg), 0o644)
	_ = os.WriteFile(filepath.Join(root, "service.last"), []byte(msg), 0o644)
}
