//go:build darwin

package hostperm

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

func probeSensorBinaryFDA() bool {
	for _, bin := range sensorProbeCandidates() {
		if probeFDADetached(bin) {
			return true
		}
	}
	return false
}

func probeProductFDA() bool {
	if ProcessHasFDA() {
		return true
	}
	if probeSensorBinaryFDA() {
		return true
	}
	for _, bin := range productFDABinaries() {
		if probeFDAProbeArg(bin, "fda-probe") || probeFDAProbeArg(bin, "--fda-probe") {
			return true
		}
		if probeCLIProtectedRead(bin) {
			return true
		}
	}
	return false
}

func productFDABinaries() []string {
	var out []string
	seen := map[string]bool{}
	add := func(p string) {
		p = strings.TrimSpace(p)
		if p == "" || seen[p] {
			return
		}
		st, err := os.Stat(p)
		if err != nil || st.IsDir() {
			return
		}
		seen[p] = true
		out = append(out, p)
	}
	for _, p := range edrctlCandidates() {
		add(p)
	}
	add("/Applications/EDR Agent.app/Contents/MacOS/edrctl")
	add("/Applications/edr.app/Contents/MacOS/edr")
	add("/Applications/EDR Agent.app/Contents/MacOS/edr-agent-ui")
	add("/Applications/edr.app/Contents/MacOS/edr-ui")
	if exe, err := os.Executable(); err == nil {
		add(exe)
		add(filepath.Join(filepath.Dir(exe), "edrctl"))
		add(filepath.Join(filepath.Dir(exe), "edr"))
	}
	return out
}

func probeFDAProbeArg(bin, arg string) bool {
	raw, err := os.ReadFile(bin)
	if err != nil || !bytes.Contains(raw, []byte("fda-probe")) {
		return false
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	return exec.CommandContext(ctx, bin, arg).Run() == nil
}

// probeCLIProtectedRead asks an already-granted CLI (edrctl) to open an
// FDA-protected path via --config. Only the error class is inspected; the
// file bytes are never used.
func probeCLIProtectedRead(bin string) bool {
	base := strings.ToLower(filepath.Base(bin))
	if base != "edrctl" && base != "edr" && base != "edr.exe" && base != "edrctl.exe" {
		return false
	}
	for _, p := range []string{
		"/var/db/locationd/clients.plist",
		systemTCC,
	} {
		if cliOpenedProtected(bin, p) {
			return true
		}
	}
	return false
}

func cliOpenedProtected(bin, protected string) bool {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, bin,
		"--socket", filepath.Join(os.TempDir(), "edr-fda-probe.sock"),
		"--addr", "http://127.0.0.1:1",
		"--config", protected,
		"status",
	)
	out, _ := cmd.CombinedOutput()
	if protectedReadLooksGranted(string(out)) {
		return true
	}
	cmd = exec.CommandContext(ctx, bin, "--config", protected, "config", "show")
	out, _ = cmd.CombinedOutput()
	return protectedReadLooksGranted(string(out))
}
