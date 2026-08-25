//go:build darwin

package main

import (
	"fmt"
	"os/exec"
	"strings"
)

func runEdrctlPrivileged(args ...string) (string, error) {
	cmd := edrctlPath()
	for _, a := range args {
		cmd += " " + shellQuote(a)
	}
	script := fmt.Sprintf(`do shell script %s with administrator privileges`, applescriptString(cmd))
	out, err := exec.Command("/usr/bin/osascript", "-e", script).CombinedOutput()
	return strings.TrimSpace(string(out)), err
}

func runInstallerPrivileged(args ...string) (string, error) {
	cmd := installerPath()
	for _, a := range args {
		cmd += " " + shellQuote(a)
	}
	script := fmt.Sprintf(`do shell script %s with administrator privileges`, applescriptString(cmd))
	out, err := exec.Command("/usr/bin/osascript", "-e", script).CombinedOutput()
	return strings.TrimSpace(string(out)), err
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
