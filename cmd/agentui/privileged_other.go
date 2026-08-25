//go:build !darwin && !windows

package main

import (
	"os/exec"
	"strings"
)

func runEdrctlPrivileged(args ...string) (string, error) {
	if _, err := exec.LookPath("pkexec"); err == nil {
		cmd := exec.Command("pkexec", append([]string{edrctlPath()}, args...)...)
		out, e := cmd.CombinedOutput()
		return strings.TrimSpace(string(out)), e
	}
	return runEdrctl(args...)
}

func runInstallerPrivileged(args ...string) (string, error) {
	if _, err := exec.LookPath("pkexec"); err == nil {
		cmd := exec.Command("pkexec", append([]string{installerPath()}, args...)...)
		out, e := cmd.CombinedOutput()
		return strings.TrimSpace(string(out)), e
	}
	cmd := exec.Command(installerPath(), args...)
	out, e := cmd.CombinedOutput()
	return strings.TrimSpace(string(out)), e
}
