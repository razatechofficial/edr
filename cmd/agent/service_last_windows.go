//go:build windows

package main

import (
	"os"
	"path/filepath"
)

func writeServiceLastError(err error) {
	dir := filepath.Join(WindowsDataRoot(), "logs")
	_ = os.MkdirAll(dir, 0o755)
	p := filepath.Join(dir, "service.last")
	if err == nil {
		_ = os.WriteFile(p, []byte("OK\n"), 0o644)
		return
	}
	_ = os.WriteFile(p, []byte(err.Error()+"\n"), 0o644)
}
