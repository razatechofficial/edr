//go:build windows

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

func init() {
	// Prefer Mesa llvmpipe when we ship opengl32.dll next to the UI (Server/RDP).
	exe, err := os.Executable()
	dir := "."
	if err == nil {
		dir = filepath.Dir(exe)
	}
	if _, err := os.Stat(filepath.Join(dir, "opengl32.dll")); err == nil {
		_ = os.Setenv("GALLIUM_DRIVER", "llvmpipe")
		_ = os.Setenv("LIBGL_ALWAYS_SOFTWARE", "1")
	}
	uiLog("init pid=%d args=%v", os.Getpid(), os.Args)
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
	proc.Call(0, uintptr(unsafe.Pointer(b)), uintptr(unsafe.Pointer(t)), 0x10) // MB_ICONERROR
}
