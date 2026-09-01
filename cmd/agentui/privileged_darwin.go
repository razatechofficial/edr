//go:build darwin

package main

import (
	"fmt"
	"os/exec"
	"strings"
)

func runEdrctlPrivileged(args ...string) (string, error) {
	return runPrivileged(edrctlPath(), args...)
}

func runInstallerPrivileged(args ...string) (string, error) {
	return runPrivileged(installerPath(), args...)
}

func runPrivileged(bin string, args ...string) (string, error) {
	script := fmt.Sprintf(`do shell script %s with administrator privileges`, applescriptString(shellCommand(bin, args)))
	out, err := exec.Command("/usr/bin/osascript", "-e", script).CombinedOutput()
	return strings.TrimSpace(string(out)), err
}

func shellCommand(bin string, args []string) string {
	cmd := shellQuote(bin)
	for _, a := range args {
		cmd += " " + shellQuote(a)
	}
	return cmd + " 2>&1"
}

func applescriptString(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `"`, `\"`)
	s = strings.ReplaceAll(s, "\r\n", "\n")
	s = strings.ReplaceAll(s, "\n", `" & return & "`)
	return `"` + s + `"`
}

func shellQuote(s string) string {
	return `'` + strings.ReplaceAll(s, `'`, `'"'"'`) + `'`
}
