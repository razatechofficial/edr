//go:build windows

package kernel

import (
	"fmt"
	"sync"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	modFwpuclnt          = windows.NewLazySystemDLL("fwpuclnt.dll")
	procFwpmEngineOpen0  = modFwpuclnt.NewProc("FwpmEngineOpen0")
	procFwpmEngineClose0 = modFwpuclnt.NewProc("FwpmEngineClose0")
)

// WFPCtl opens the local Windows Filtering Platform engine for control-plane health checks.
type WFPCtl struct {
	mu sync.Mutex

	h       windows.Handle
	lastErr string
}

// NewWFPCtl constructs an empty WFP control handle.
func NewWFPCtl() *WFPCtl { return &WFPCtl{} }

// Start opens a session to the local WFP engine (FwpmEngineOpen0).
func (w *WFPCtl) Start() error {
	if w == nil {
		return nil
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.h != 0 {
		return nil
	}
	var h windows.Handle
	r0, _, err := procFwpmEngineOpen0.Call(
		0, // serverName (local)
		0, // RPC_C_AUTHN_DEFAULT
		0, // auth identity
		0, // session template
		uintptr(unsafe.Pointer(&h)),
	)
	if r0 != 0 {
		if err != nil {
			w.lastErr = err.Error()
		} else {
			w.lastErr = fmt.Sprintf("Win32_%d", r0)
		}
		return fmt.Errorf("%w: %s", ErrWFPNotAvailable, w.lastErr)
	}
	w.h = h
	w.lastErr = ""
	return nil
}

// Stop closes the WFP engine handle.
func (w *WFPCtl) Stop() {
	if w == nil {
		return
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.h != 0 {
		_, _, _ = procFwpmEngineClose0.Call(uintptr(w.h))
		w.h = 0
	}
}

// Health reports whether the WFP engine handle is active.
func (w *WFPCtl) Health() map[string]any {
	if w == nil {
		return map[string]any{"engine_open": false}
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	out := map[string]any{"engine_open": w.h != 0}
	if w.lastErr != "" {
		out["last_error"] = w.lastErr
	}
	return out
}
