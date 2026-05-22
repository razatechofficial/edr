//go:build windows

package kernel

import (
	"fmt"
	"sync"
	"unsafe"

	"golang.org/x/sys/windows"
)

// WDMProtect talks to edr_protect.sys over IOCTL for ObRegisterCallbacks PID protection.
type WDMProtect struct {
	mu     sync.Mutex
	device string
	h      windows.Handle
	lastErr string
}

var globalWDMProtect = &WDMProtect{device: DefaultWDMProtectDevice}

// GlobalWDMProtect returns the process-wide WDM protection client.
func GlobalWDMProtect() *WDMProtect { return globalWDMProtect }

// SetDevice overrides the symlink path (for tests).
func (w *WDMProtect) SetDevice(path string) {
	w.mu.Lock()
	w.device = path
	w.mu.Unlock()
}

// Connect opens \\.\EdrProtect when the signed driver is installed.
func (w *WDMProtect) Connect() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.h != 0 {
		return nil
	}
	path := w.device
	if path == "" {
		path = DefaultWDMProtectDevice
	}
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		w.lastErr = err.Error()
		return err
	}
	h, err := windows.CreateFile(
		p,
		windows.GENERIC_READ|windows.GENERIC_WRITE,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE,
		nil,
		windows.OPEN_EXISTING,
		0,
		0,
	)
	if err != nil {
		w.lastErr = err.Error()
		return fmt.Errorf("wdm_protect: open %s: %w", path, err)
	}
	w.h = h
	w.lastErr = ""
	return nil
}

// Close releases the device handle.
func (w *WDMProtect) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.h == 0 {
		return nil
	}
	err := windows.CloseHandle(w.h)
	w.h = 0
	return err
}

// RegisterPID adds a process to the kernel protected-PID list.
func (w *WDMProtect) RegisterPID(pid uint32) error {
	if pid == 0 {
		return fmt.Errorf("wdm_protect: invalid pid")
	}
	if err := w.Connect(); err != nil {
		return err
	}
	w.mu.Lock()
	h := w.h
	w.mu.Unlock()
	var in uint32 = pid
	var returned uint32
	return windows.DeviceIoControl(
		h,
		IOCTL_EDRAddProtectedPID,
		(*byte)(unsafe.Pointer(&in)),
		uint32(unsafe.Sizeof(in)),
		nil,
		0,
		&returned,
		nil,
	)
}

// UnregisterPID removes a PID from the protected list.
func (w *WDMProtect) UnregisterPID(pid uint32) error {
	if err := w.Connect(); err != nil {
		return err
	}
	w.mu.Lock()
	h := w.h
	w.mu.Unlock()
	var in uint32 = pid
	var returned uint32
	return windows.DeviceIoControl(
		h,
		IOCTL_EDRRemoveProtectedPID,
		(*byte)(unsafe.Pointer(&in)),
		uint32(unsafe.Sizeof(in)),
		nil,
		0,
		&returned,
		nil,
	)
}

// Status queries driver health when connected.
func (w *WDMProtect) Status() (WDMProtectStatus, error) {
	var out WDMProtectStatus
	if err := w.Connect(); err != nil {
		return out, err
	}
	w.mu.Lock()
	h := w.h
	w.mu.Unlock()
	var returned uint32
	err := windows.DeviceIoControl(
		h,
		IOCTL_EDRGetStatus,
		nil,
		0,
		(*byte)(unsafe.Pointer(&out)),
		uint32(unsafe.Sizeof(out)),
		&returned,
		nil,
	)
	return out, err
}

// Health exports monitoring posture fields.
func (w *WDMProtect) Health() map[string]any {
	h := map[string]any{
		"device":    w.device,
		"connected": false,
	}
	if w == nil {
		h["state"] = "nil"
		return h
	}
	w.mu.Lock()
	if w.h != 0 {
		h["connected"] = true
	}
	if w.lastErr != "" {
		h["last_error"] = w.lastErr
	}
	w.mu.Unlock()
	st, err := w.Status()
	if err != nil {
		h["status_error"] = err.Error()
		return h
	}
	h["connected"] = true
	h["protected_pid_count"] = st.ProtectedPidCount
	h["ob_callbacks"] = st.ObCallbacksRegistered != 0
	return h
}

// RegisterCurrentProcess connects and registers os.Getpid() with edr_protect.sys.
func RegisterCurrentProcessWithWDM() map[string]any {
	out := map[string]any{"attempted": true}
	w := GlobalWDMProtect()
	pid := uint32(windows.GetCurrentProcessId())
	if err := w.RegisterPID(pid); err != nil {
		out["connected"] = false
		out["error"] = err.Error()
		out["hint"] = "Install signed edr_protect.sys and start EdrProtect service"
		return out
	}
	out["connected"] = true
	out["registered_pid"] = pid
	if st, err := w.Status(); err == nil {
		out["protected_pid_count"] = st.ProtectedPidCount
		out["ob_callbacks"] = st.ObCallbacksRegistered != 0
	}
	return out
}
