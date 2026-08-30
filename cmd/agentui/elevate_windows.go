//go:build windows

package main

import (
	"os"
	"os/exec"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

func processIsAdmin() bool {
	return windows.GetCurrentProcessToken().IsElevated()
}

func maybeElevate() error {
	if processIsAdmin() {
		return nil
	}
	for _, a := range os.Args[1:] {
		if a == "--already-elevated" {
			// UAC was already requested; do not ShellExecute again (cmd/UAC loop).
			return nil
		}
	}
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	args := append([]string{"--already-elevated"}, os.Args[1:]...)
	verb, _ := windows.UTF16PtrFromString("runas")
	file, _ := windows.UTF16PtrFromString(exe)
	params, _ := windows.UTF16PtrFromString(strings.Join(args, " "))
	mod := windows.NewLazySystemDLL("shell32.dll")
	proc := mod.NewProc("ShellExecuteW")
	ret, _, callErr := proc.Call(0, uintptr(unsafe.Pointer(verb)), uintptr(unsafe.Pointer(file)), uintptr(unsafe.Pointer(params)), 0, 1)
	// ShellExecute: >32 is success. 1223 (ERROR_CANCELLED) is also >32.
	if ret <= 32 || ret == 1223 {
		if callErr != nil {
			return callErr
		}
		return windows.ERROR_CANCELLED
	}
	os.Exit(0)
	return nil
}

func runEdrctlPrivileged(args ...string) (string, error) {
	return runEdrctl(args...)
}

func runInstallerPrivileged(args ...string) (string, error) {
	cmd := exec.Command(installerPath(), args...)
	hideConsole(cmd)
	out, err := cmd.CombinedOutput()
	return strings.TrimSpace(string(out)), err
}
