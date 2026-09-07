//go:build windows

package main

import (
	"os"
	"path/filepath"
	"time"
)

func windowsDataRootForLogs() string { return WindowsDataRoot() }

func hasServiceConfigArg() bool {
	for _, a := range os.Args[1:] {
		if a == "--config" {
			return true
		}
	}
	return false
}

func writeAgentBoot(msg string) {
	root := WindowsDataRoot()
	_ = os.MkdirAll(root, 0o755)
	line := time.Now().UTC().Format(time.RFC3339) + " " + msg + "\n"
	p := filepath.Join(root, "agent.boot")
	f, err := os.OpenFile(p, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return
	}
	_, _ = f.WriteString(line)
	_ = f.Close()
}

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
