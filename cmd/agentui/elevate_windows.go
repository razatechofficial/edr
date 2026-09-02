//go:build windows

package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

const seeMaskNoCloseProcess = 0x00000040

type shellExecuteInfo struct {
	CbSize       uint32
	FMask        uint32
	Hwnd         windows.Handle
	LpVerb       *uint16
	LpFile       *uint16
	LpParameters *uint16
	LpDirectory  *uint16
	NShow        int32
	HInstApp     windows.Handle
	LpIDList     uintptr
	LpClass      *uint16
	HKeyClass    windows.Handle
	DwHotKey     uint32
	HIcon        windows.Handle
	HProcess     windows.Handle
}

var procShellExecuteExW = windows.NewLazySystemDLL("shell32.dll").NewProc("ShellExecuteExW")

func processIsAdmin() bool {
	return windows.GetCurrentProcessToken().IsElevated()
}

func hasArg(name string) bool {
	for _, a := range os.Args[1:] {
		if a == name {
			return true
		}
	}
	return false
}

func maybeElevate() error {
	if processIsAdmin() || flagTray {
		return nil
	}
	if hasArg("--already-elevated") {
		return nil
	}
	if err := relaunchElevated(os.Args[1:]...); err != nil {
		if err == windows.ERROR_CANCELLED {
			return nil
		}
		return err
	}
	os.Exit(0)
	return nil
}

func relaunchElevated(extra ...string) error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	args := append([]string{"--already-elevated"}, extra...)
	return shellRunAs(exe, args, true, false)
}

func runEdrctlPrivileged(args ...string) (string, error) {
	if processIsAdmin() {
		return runEdrctl(args...)
	}
	if err := shellRunAs(edrctlPath(), args, false, true); err != nil {
		return "", err
	}
	return "", nil
}

func runInstallerPrivileged(args ...string) (string, error) {
	if processIsAdmin() {
		cmd := exec.Command(installerPath(), args...)
		hideConsole(cmd)
		out, err := cmd.CombinedOutput()
		return strings.TrimSpace(string(out)), err
	}
	if err := shellRunAs(installerPath(), args, false, true); err != nil {
		return "", err
	}
	return "", nil
}

func runAgentInstallPrivileged() error {
	bin := sensorBinaryPath()
	if processIsAdmin() {
		cmd := exec.Command(bin, "--install")
		hideConsole(cmd)
		out, err := cmd.CombinedOutput()
		msg := strings.TrimSpace(string(out))
		if err != nil {
			if serviceAlreadyPresentError(msg + " " + err.Error()) {
				return nil
			}
			return fmt.Errorf("register service: %w (%s)", err, msg)
		}
		return nil
	}
	return shellRunAs(bin, []string{"--install"}, false, true)
}

func shellRunAs(exe string, args []string, show, wait bool) error {
	exe, err := filepath.Abs(exe)
	if err != nil {
		return err
	}
	verb, err := windows.UTF16PtrFromString("runas")
	if err != nil {
		return err
	}
	file, err := windows.UTF16PtrFromString(exe)
	if err != nil {
		return err
	}
	var params *uint16
	if line := quoteArgs(args); line != "" {
		params, err = windows.UTF16PtrFromString(line)
		if err != nil {
			return err
		}
	}
	showCmd := int32(windows.SW_HIDE)
	if show {
		showCmd = windows.SW_SHOWNORMAL
	}
	info := shellExecuteInfo{
		FMask:        seeMaskNoCloseProcess,
		LpVerb:       verb,
		LpFile:       file,
		LpParameters: params,
		NShow:        showCmd,
	}
	info.CbSize = uint32(unsafe.Sizeof(info))
	r, _, callErr := procShellExecuteExW.Call(uintptr(unsafe.Pointer(&info)))
	if r == 0 {
		if callErr != nil {
			return callErr
		}
		return windows.ERROR_INVALID_FUNCTION
	}
	if info.HProcess == 0 {
		return nil
	}
	if !wait {
		_ = windows.CloseHandle(info.HProcess)
		return nil
	}
	defer windows.CloseHandle(info.HProcess)
	_, _ = windows.WaitForSingleObject(info.HProcess, windows.INFINITE)
	var code uint32
	if err := windows.GetExitCodeProcess(info.HProcess, &code); err != nil {
		return err
	}
	if code != 0 {
		return fmt.Errorf("elevated process exited %d", code)
	}
	return nil
}

func quoteArgs(args []string) string {
	if len(args) == 0 {
		return ""
	}
	parts := make([]string, len(args))
	for i, a := range args {
		parts[i] = syscall.EscapeArg(a)
	}
	return strings.Join(parts, " ")
}
