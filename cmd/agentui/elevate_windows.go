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
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	verb, _ := windows.UTF16PtrFromString("runas")
	file, _ := windows.UTF16PtrFromString(exe)
	params, _ := windows.UTF16PtrFromString(strings.Join(os.Args[1:], " "))
	mod := windows.NewLazySystemDLL("shell32.dll")
	proc := mod.NewProc("ShellExecuteW")
	ret, _, callErr := proc.Call(0, uintptr(unsafe.Pointer(verb)), uintptr(unsafe.Pointer(file)), uintptr(unsafe.Pointer(params)), 0, 5)
	if ret <= 32 {
		return callErr
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
