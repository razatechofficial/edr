package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

func edrctlPath() string {
	var cands []string
	// Prefer the binary next to this UI so a local/dev .app uses matching edrctl,
	// not a stale copy in /usr/local/bin.
	if exe, err := os.Executable(); err == nil {
		dir := filepath.Dir(exe)
		cands = append(cands,
			filepath.Join(dir, "edrctl"),
			filepath.Join(dir, "edrctl.exe"),
			filepath.Join(dir, "edr"),
			filepath.Join(dir, "edr.exe"),
		)
	}
	if runtime.GOOS == "darwin" {
		cands = append(cands,
			"/usr/local/bin/edrctl",
			"/usr/local/bin/edr",
			"/Applications/EDR Agent.app/Contents/MacOS/edrctl",
		)
	}
	if runtime.GOOS == "windows" {
		if pf := os.Getenv("ProgramFiles"); pf != "" {
			cands = append(cands, filepath.Join(pf, "EDR Agent", "edrctl.exe"), filepath.Join(pf, "EDR Agent", "edr.exe"))
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
	if p, err := exec.LookPath("edrctl"); err == nil {
		return p
	}
	return "edrctl"
}

func installerPath() string {
	if p := embeddedSetupInstallerPath(); p != "" {
		return p
	}
	var cands []string
	if exe, err := os.Executable(); err == nil {
		dir := filepath.Dir(exe)
		cands = append(cands,
			filepath.Join(dir, "edr-installer"),
			filepath.Join(dir, "edr-installer.exe"),
		)
	}
	if runtime.GOOS == "darwin" {
		cands = append(cands,
			"/Applications/EDR Agent.app/Contents/MacOS/edr-installer",
			"/usr/local/bin/edr-installer",
		)
	}
	if runtime.GOOS == "windows" {
		if pf := os.Getenv("ProgramFiles"); pf != "" {
			cands = append(cands, filepath.Join(pf, "EDR Agent", "edr-installer.exe"))
		}
	}
	if runtime.GOOS == "linux" {
		cands = append(cands, "/usr/bin/edr-installer", "/usr/local/bin/edr-installer")
	}
	for _, p := range cands {
		if st, err := os.Stat(p); err == nil && !st.IsDir() {
			return p
		}
	}
	if p, err := exec.LookPath("edr-installer"); err == nil {
		return p
	}
	return "edr-installer"
}

// systemAgentCandidates is where a finished per-machine install puts the sensor.
// Sibling binaries inside EDR Agent.app / Setup.exe do not count — those are
// the payload the attended wizard copies on Accept.
func systemAgentCandidates() []string {
	switch runtime.GOOS {
	case "darwin":
		return []string{
			"/usr/local/libexec/edr-agent.app/Contents/MacOS/edr-agent",
			"/Library/Application Support/EDR/bin/edr-agent",
			"/usr/local/bin/edr-agent",
		}
	case "windows":
		pf := os.Getenv("ProgramFiles")
		if pf == "" {
			pf = `C:\Program Files`
		}
		return []string{filepath.Join(pf, "EDR Agent", "edr-agent.exe")}
	default:
		return []string{"/usr/local/bin/edr-agent", "/usr/bin/edr-agent"}
	}
}

func agentInstalled() bool {
	for _, p := range systemAgentCandidates() {
		if st, err := os.Stat(p); err == nil && !st.IsDir() {
			return true
		}
	}
	return false
}

func installerPresent() bool {
	p := installerPath()
	if p == "edr-installer" {
		_, err := exec.LookPath("edr-installer")
		return err == nil
	}
	st, err := os.Stat(p)
	return err == nil && !st.IsDir()
}

func runEdrctl(args ...string) (string, error) {
	cmd := exec.Command(edrctlPath(), args...)
	hideConsole(cmd)
	out, err := cmd.CombinedOutput()
	return strings.TrimSpace(string(out)), err
}
