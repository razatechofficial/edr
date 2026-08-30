//go:build !windows

package collector

import "os/exec"

func hideConsole(*exec.Cmd) {}
