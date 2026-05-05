//go:build windows

package kernel

import (
	"fmt"
	"sync"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	modFltLib                          = windows.NewLazySystemDLL("fltlib.dll")
	procFilterConnectCommunicationPort = modFltLib.NewProc("FilterConnectCommunicationPort")
)

// MinifilterCtl maintains a user-mode handle to a minifilter communication port.
// When no port name is configured, Start is a no-op and Health reports skipped.
type MinifilterCtl struct {
	mu sync.Mutex

	portUTF16 *uint16
	h         windows.Handle
	lastErr   string
}

// NewMinifilterCtl prepares a control handle for the given port name (e.g. "\\EdrPort").
func NewMinifilterCtl(portName string) *MinifilterCtl {
	if portName == "" {
		return &MinifilterCtl{}
	}
	u, err := windows.UTF16PtrFromString(portName)
	if err != nil {
		return &MinifilterCtl{lastErr: err.Error()}
	}
	return &MinifilterCtl{portUTF16: u}
}

// Start connects to the minifilter communication port.
func (m *MinifilterCtl) Start() error {
	if m == nil || m.portUTF16 == nil {
		return nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.h != 0 {
		return nil
	}
	var h windows.Handle
	r0, _, _ := procFilterConnectCommunicationPort.Call(
		uintptr(unsafe.Pointer(m.portUTF16)),
		0,
		0,
		0,
		0,
		uintptr(unsafe.Pointer(&h)),
	)
	if r0 != 0 {
		m.lastErr = fmt.Sprintf("HRESULT_%08x", uint32(r0))
		return fmt.Errorf("%w: %s", ErrMinifilterDriverNotPresent, m.lastErr)
	}
	if h == 0 {
		m.lastErr = "zero_handle"
		return ErrMinifilterDriverNotPresent
	}
	m.h = h
	m.lastErr = ""
	return nil
}

// Stop closes the communication port handle.
func (m *MinifilterCtl) Stop() {
	if m == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.h != 0 {
		_ = windows.CloseHandle(m.h)
		m.h = 0
	}
}

// Health returns attachment status for monitoring_health.json.
func (m *MinifilterCtl) Health() map[string]any {
	if m == nil {
		return map[string]any{"connected": false}
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.portUTF16 == nil && m.lastErr == "" {
		return map[string]any{"connected": false, "skipped": true}
	}
	out := map[string]any{"connected": m.h != 0}
	if m.lastErr != "" {
		out["last_error"] = m.lastErr
	}
	return out
}
