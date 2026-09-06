//go:build windows

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

func init() {
	prepareWindowsUIRuntime()
}

// prepareWindowsUIRuntime makes the Fyne console work on Windows 10/11 Pro,
// Enterprise, and Server (including Hyper-V / RDP) without manual setup:
// prefer app-dir Mesa opengl32.dll and force software GL when that DLL ships.
func prepareWindowsUIRuntime() {
	exe, err := os.Executable()
	dir := "."
	if err == nil {
		dir = filepath.Dir(exe)
		_ = os.Chdir(dir)
		setDLLDirectory(dir)
	}

	mesa := filepath.Join(dir, "opengl32.dll")
	gallium := filepath.Join(dir, "libgallium_wgl.dll")
	hasMesa := false
	if st, err := os.Stat(mesa); err == nil && !st.IsDir() {
		if st.Size() > 1<<20 {
			hasMesa = true
		} else if gst, gerr := os.Stat(gallium); gerr == nil && !gst.IsDir() && gst.Size() > 1<<20 {
			hasMesa = true
		}
	}
	// Prefer values the parent launcher already set. Do not set
	// MESA_GL_VERSION_OVERRIDE here; that has crashed Fyne on Server.
	if hasMesa && os.Getenv("GALLIUM_DRIVER") == "" && (windowsProductIsServer() || windowsIsRemoteSession()) {
		_ = os.Setenv("GALLIUM_DRIVER", "llvmpipe")
		_ = os.Setenv("LIBGL_ALWAYS_SOFTWARE", "1")
	}

	uiLog("init pid=%d go=%s os=%s/%s server=%v rdp=%v mesa=%v args=%v",
		os.Getpid(), runtime.Version(), runtime.GOOS, runtime.GOARCH,
		windowsProductIsServer(), windowsIsRemoteSession(), hasMesa, os.Args)
}

func windowsIsRemoteSession() bool {
	user32 := windows.NewLazySystemDLL("user32.dll")
	proc := user32.NewProc("GetSystemMetrics")
	if proc.Find() != nil {
		return false
	}
	r, _, _ := proc.Call(0x1000) // SM_REMOTESESSION
	return r != 0
}

func setDLLDirectory(dir string) {
	p, err := windows.UTF16PtrFromString(dir)
	if err != nil {
		return
	}
	mod := windows.NewLazySystemDLL("kernel32.dll")
	if proc := mod.NewProc("SetDllDirectoryW"); proc.Find() == nil {
		_, _, _ = proc.Call(uintptr(unsafe.Pointer(p)))
	}
}

func windowsProductIsServer() bool {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows NT\CurrentVersion`, registry.QUERY_VALUE)
	if err != nil {
		return false
	}
	defer k.Close()
	if pt, _, err := k.GetStringValue("InstallationType"); err == nil {
		pt = strings.ToLower(strings.TrimSpace(pt))
		if strings.HasPrefix(pt, "server") || pt == "nano server" {
			return true
		}
	}
	if name, _, err := k.GetStringValue("ProductName"); err == nil {
		return strings.Contains(strings.ToLower(name), "server")
	}
	return false
}

func uiLog(format string, args ...any) {
	pd := os.Getenv("ProgramData")
	if pd == "" {
		pd = `C:\ProgramData`
	}
	dir := filepath.Join(pd, "EDR Agent", "logs")
	_ = os.MkdirAll(dir, 0o755)
	f, err := os.OpenFile(filepath.Join(dir, "ui.log"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return
	}
	defer f.Close()
	_, _ = fmt.Fprintf(f, time.Now().UTC().Format(time.RFC3339)+" "+format+"\n", args...)
}

func uiAlert(title, body string) {
	uiLog("alert %s: %s", title, body)
	t, _ := windows.UTF16PtrFromString(title)
	b, _ := windows.UTF16PtrFromString(body)
	user32 := windows.NewLazySystemDLL("user32.dll")
	proc := user32.NewProc("MessageBoxW")
	proc.Call(0, uintptr(unsafe.Pointer(b)), uintptr(unsafe.Pointer(t)), 0x10)
}
