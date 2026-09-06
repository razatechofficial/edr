//go:build windows

package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
)

func launchNativeConsoleIfNeeded() bool {
	return relaunchWithMesaEnv()
}

// relaunchWithMesaEnv starts a child of this exe with Mesa variables already
// set. GLFW/CGO loads opengl32.dll at process start, so env must exist before
// that — a parent process is the supported way to run Fyne on Windows Server.
func relaunchWithMesaEnv() bool {
	if os.Getenv("EDR_MESA_READY") == "1" {
		return false
	}
	if !windowsProductIsServer() && !windowsIsRemoteSession() {
		return false
	}
	exe, err := os.Executable()
	if err != nil {
		return false
	}
	dir := filepath.Dir(exe)
	applyMesaLaunchEnv(dir)
	cmd := exec.Command(exe, os.Args[1:]...)
	cmd.Dir = dir
	cmd.Env = os.Environ()
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: false}
	if err := cmd.Start(); err != nil {
		uiLog("mesa relaunch failed: %v", err)
		return false
	}
	uiLog("relaunched with Mesa software OpenGL pid=%d", cmd.Process.Pid)
	return true
}

func applyMesaLaunchEnv(dir string) {
	_ = os.Setenv("EDR_MESA_READY", "1")
	_ = os.Setenv("GALLIUM_DRIVER", "llvmpipe")
	_ = os.Setenv("LIBGL_ALWAYS_SOFTWARE", "1")
	_ = os.Setenv("MESA_LOADER_DRIVER_OVERRIDE", "llvmpipe")
	path := os.Getenv("PATH")
	if dir != "" && !strings.Contains(strings.ToLower(path), strings.ToLower(dir)) {
		_ = os.Setenv("PATH", dir+string(os.PathListSeparator)+path)
	}
}
