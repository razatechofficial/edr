//go:build windows

package main

import (
	"os/exec"
	"syscall"
)

func hideConsole(cmd *exec.Cmd) {
	if cmd == nil {
		return
	}
	cmd.SysProcAttr = &syscall.SysProcAttr{
		CreationFlags: 0x08000000, // CREATE_NO_WINDOW — HideWindow still flashes a console
	}
}
