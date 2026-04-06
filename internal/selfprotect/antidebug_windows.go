//go:build windows

package selfprotect

import (
	"fmt"
	"os"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	kernel32                       = windows.NewLazyDLL("kernel32.dll")
	ntdll                          = windows.NewLazyDLL("ntdll.dll")
	procIsDebuggerPresent          = kernel32.NewProc("IsDebuggerPresent")
	procCheckRemoteDebuggerPresent = kernel32.NewProc("CheckRemoteDebuggerPresent")
	procNtSetInformationThread     = ntdll.NewProc("NtSetInformationThread")
)

// DetectDebugger returns true if a debugger (local or remote) is attached
// to the current process. On Windows it calls IsDebuggerPresent and
// CheckRemoteDebuggerPresent.
func DetectDebugger() bool {
	ret, _, _ := procIsDebuggerPresent.Call()
	if ret != 0 {
		return true
	}

	handle, err := windows.GetCurrentProcess()
	if err != nil {
		return false
	}
	var debugged int32
	ret, _, _ = procCheckRemoteDebuggerPresent.Call(
		uintptr(handle),
		uintptr(unsafe.Pointer(&debugged)),
	)
	if ret != 0 && debugged != 0 {
		return true
	}

	for _, env := range []string{"_NO_DEBUG_HEAP"} {
		if os.Getenv(env) != "" {
			return true
		}
	}
	return false
}

// ProtectProcess hides the current thread from debuggers via
// NtSetInformationThread(ThreadHideFromDebugger).
func ProtectProcess() error {
	const threadHideFromDebugger = 0x11
	thread, err := windows.GetCurrentThread()
	if err != nil {
		return fmt.Errorf("antidebug: GetCurrentThread: %w", err)
	}
	ret, _, _ := procNtSetInformationThread.Call(
		uintptr(thread),
		threadHideFromDebugger,
		0,
		0,
	)
	if ret != 0 {
		return fmt.Errorf("antidebug: NtSetInformationThread NTSTATUS %#x", ret)
	}
	return nil
}
