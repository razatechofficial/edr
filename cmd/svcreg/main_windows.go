//go:build windows

// Command svcreg registers the per-machine EDRAgent service via SCM.
// Built with CGO_ENABLED=0 so MSI/custom actions never depend on libyara/MinGW DLLs.
package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/razatechofficial/edr/internal/hostperm"
	"github.com/razatechofficial/edr/internal/platform"
)

func main() {
	exe := filepath.Join(platform.InstallDir(), "edr-agent.exe")
	cfg := filepath.Join(platform.DataDir(), "config.yml")
	if len(os.Args) >= 2 && os.Args[1] != "" {
		exe = os.Args[1]
	}
	if len(os.Args) >= 3 && os.Args[2] != "" {
		cfg = os.Args[2]
	}
	if err := hostperm.EnsureSensorService(exe, cfg); err != nil {
		fmt.Fprintf(os.Stderr, "svcreg: %v\n", err)
		os.Exit(1)
	}
}
