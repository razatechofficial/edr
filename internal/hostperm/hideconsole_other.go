//go:build !windows

package hostperm

import "os/exec"

func hideConsole(*exec.Cmd) {}
