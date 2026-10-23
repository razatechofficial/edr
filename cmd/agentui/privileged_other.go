//go:build !darwin && !windows

package main

import (
	"os/exec"
	"strings"
)

func runEdrctlPrivileged(args ...string) (string, error) {
	if _, err := exec.LookPath("pkexec"); err == nil {
		// exec.Command takes the program and its arguments separately;
		// passing one flattened argv does not compile. It never did,
		// and nothing noticed because CI built this package on no
		// platform where this file applies.
		argv := append([]string{edrctlPath()}, args...)
		cmd := exec.Command("pkexec", argv...)
		out, e := cmd.CombinedOutput()
		return strings.TrimSpace(string(out)), e
	}
	return runEdrctl(args...)
}
