//go:build !windows

package xdrclient

import "os/exec"

func hideConsole(*exec.Cmd) {}
