//go:build windows

// Command svcreg registers the per-machine EDRAgent service via SCM.
// Built with CGO_ENABLED=0 so MSI/custom actions never depend on libyara/MinGW DLLs.
// Built as WINDOWS subsystem so msiexec never shows a blank console.
package main

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/razatechofficial/edr/internal/hostperm"
	"github.com/razatechofficial/edr/internal/platform"
)

func main() {
	if len(os.Args) >= 2 && os.Args[1] == "--start" {
		logf("start begin")
		if err := hostperm.StartSensorService(); err != nil {
			logf("start fail: %v", err)
			writeLast("FAIL start: " + err.Error())
			os.Exit(1)
		}
		logf("start ok")
		writeLast("OK start")
		return
	}
	exe := filepath.Join(platform.InstallDir(), "edr-agent.exe")
	cfg := filepath.Join(platform.DataDir(), "config.yml")
	if len(os.Args) >= 2 && os.Args[1] != "" && os.Args[1] != "--start" {
		exe = os.Args[1]
	}
	if len(os.Args) >= 3 && os.Args[2] != "" {
		cfg = os.Args[2]
	}
	logf("begin exe=%s cfg=%s", exe, cfg)
	if err := hostperm.EnsureSensorService(exe, cfg); err != nil {
		logf("fail: %v", err)
		writeLast("FAIL: " + err.Error())
		os.Exit(1)
	}
	logf("ok")
	writeLast("OK")
}

func writeLast(msg string) {
	dir := platform.LogDir()
	_ = os.MkdirAll(dir, 0o755)
	_ = os.WriteFile(filepath.Join(dir, "svcreg.last"), []byte(msg+"\n"), 0o644)
}

func logf(format string, args ...any) {
	dir := platform.LogDir()
	_ = os.MkdirAll(dir, 0o755)
	f, err := os.OpenFile(filepath.Join(dir, "msi_register.log"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return
	}
	defer f.Close()
	_, _ = fmt.Fprintf(f, time.Now().UTC().Format(time.RFC3339)+" svcreg "+format+"\n", args...)
}
