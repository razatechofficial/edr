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

	"github.com/razatechofficial/edr/internal/hostperm"
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
	// Privileged actions (service start/uninstall) already use ShellExecute
	// runas. Elevating the whole Fyne console breaks on Windows Server / RDP
	// (WGL OpenGL) and made Start Menu look like a no-op when UAC failed.
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

func startSensorServicePrivileged() error {
	if processIsAdmin() {
		return hostperm.StartSensorService()
	}
	sys := filepath.Join(os.Getenv("SystemRoot"), "System32", "sc.exe")
	if os.Getenv("SystemRoot") == "" {
		sys = `C:\Windows\System32\sc.exe`
	}
	if err := shellRunAs(sys, []string{"start", "EDRAgent"}, false, true); err != nil {
		msg := strings.ToLower(err.Error())
		if strings.Contains(msg, "already") || strings.Contains(msg, "1056") {
			return nil
		}
		return err
	}
	return nil
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
	pd := os.Getenv("ProgramData")
	if pd == "" {
		pd = `C:\ProgramData`
	}
	cfg := filepath.Join(pd, "EDR Agent", "config.yml")
	svcreg := filepath.Join(filepath.Dir(bin), "edr-svcreg.exe")
	register := func() error {
		if err := hostperm.EnsureSensorService(bin, cfg); err != nil {
			if st, serr := os.Stat(svcreg); serr == nil && !st.IsDir() {
				cmd := exec.Command(svcreg, bin, cfg)
				hideConsole(cmd)
				out, rerr := cmd.CombinedOutput()
				if rerr != nil {
					detail := strings.TrimSpace(string(out))
					if detail == "" {
						detail = readSvcRegLastError()
					}
					if detail == "" {
						detail = rerr.Error()
					}
					return fmt.Errorf("register service: %s", detail)
				}
			} else {
				return err
			}
		}
		if !hostperm.SensorRegistered() {
			if detail := readSvcRegLastError(); detail != "" {
				return fmt.Errorf("EDRAgent still missing after register: %s", detail)
			}
			return fmt.Errorf("EDRAgent still missing after register")
		}
		return nil
	}
	if processIsAdmin() {
		if err := register(); err != nil {
			if serviceAlreadyPresentError(err.Error()) {
				return nil
			}
			return err
		}
		return nil
	}
	if st, err := os.Stat(svcreg); err == nil && !st.IsDir() {
		if err := shellRunAs(svcreg, []string{bin, cfg}, false, true); err != nil {
			detail := readSvcRegLastError()
			if detail != "" {
				return fmt.Errorf("register service: %s", detail)
			}
			return fmt.Errorf("register service: %w", err)
		}
		if hostperm.SensorRegistered() {
			return nil
		}
		return fmt.Errorf("EDRAgent still missing after register")
	}
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	return shellRunAs(exe, []string{"--register-service", "--already-elevated"}, false, true)
}

func readSvcRegLastError() string {
	pd := os.Getenv("ProgramData")
	if pd == "" {
		pd = `C:\ProgramData`
	}
	raw, err := os.ReadFile(filepath.Join(pd, "EDR Agent", "logs", "svcreg.last"))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(raw))
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
	event, _ := windows.WaitForSingleObject(info.HProcess, 45000)
	if event == 0x00000102 { // WAIT_TIMEOUT
		return fmt.Errorf("Administrator approval timed out. Allow the prompt, then Start again.")
	}
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
