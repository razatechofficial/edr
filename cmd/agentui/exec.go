package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

func edrctlPath() string {
	exe, err := os.Executable()
	if err == nil {
		dir := filepath.Dir(exe)
		cands := []string{
			filepath.Join(dir, "edrctl"),
			filepath.Join(dir, "edrctl.exe"),
			filepath.Join(dir, "edr"),
			filepath.Join(dir, "edr.exe"),
		}
		if runtime.GOOS == "darwin" {
			cands = append(cands, "/usr/local/bin/edrctl", "/usr/local/bin/edr")
		}
		if runtime.GOOS == "windows" {
			pf := os.Getenv("ProgramFiles")
			if pf != "" {
				cands = append(cands, filepath.Join(pf, "EDR Agent", "edrctl.exe"))
			}
		}
		if runtime.GOOS == "linux" {
			cands = append(cands, "/usr/bin/edrctl", "/usr/local/bin/edrctl")
		}
		for _, p := range cands {
			if st, err := os.Stat(p); err == nil && !st.IsDir() {
				return p
			}
		}
	}
	if p, err := exec.LookPath("edrctl"); err == nil {
		return p
	}
	return "edrctl"
}

func runEdrctl(args ...string) (string, error) {
	cmd := exec.Command(edrctlPath(), args...)
	out, err := cmd.CombinedOutput()
	return strings.TrimSpace(string(out)), err
}
