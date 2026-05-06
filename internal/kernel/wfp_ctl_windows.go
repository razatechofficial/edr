//go:build windows

package kernel

import (
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

func classifyWFPEngineErr(r0 uintptr, sysErr error) (causeClass string, err error) {
	code := uint32(r0)
	switch code {
	case 1722, 1753, 1460, 1707: // RPC_S_SERVER_UNAVAILABLE, EPT_S_NOT_REGISTERED, etc.
		return "transient", fmt.Errorf("%w: Win32_%d", ErrControlPlaneTransient, code)
	case 0:
		if sysErr != nil {
			return "transient", fmt.Errorf("%w: %v", ErrControlPlaneTransient, sysErr)
		}
		return "transient", ErrControlPlaneTransient
	default:
		if sysErr != nil {
			return "permanent", fmt.Errorf("%w: %v", ErrWFPNotAvailable, sysErr)
		}
		return "permanent", fmt.Errorf("%w: Win32_%d", ErrWFPNotAvailable, code)
	}
}

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
	state   string
	lastOK  int64

	startAttempts atomic.Uint64
	startFailures atomic.Uint64
	recoveries    atomic.Uint64

	causeClass         string
	lastRecoverOutcome string
}

// NewWFPCtl constructs an empty WFP control handle.
func NewWFPCtl() *WFPCtl { return &WFPCtl{state: "init"} }

// Start opens a session to the local WFP engine (FwpmEngineOpen0).
func (w *WFPCtl) Start() error {
	if w == nil {
		return nil
	}
	w.startAttempts.Add(1)
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.h != 0 {
		w.state = "running"
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
		cc, werr := classifyWFPEngineErr(r0, err)
		if err != nil {
			w.lastErr = err.Error()
		} else {
			w.lastErr = fmt.Sprintf("Win32_%d", r0)
		}
		w.state = "degraded"
		w.startFailures.Add(1)
		w.causeClass = cc
		w.lastRecoverOutcome = "start_failed"
		return werr
	}
	w.h = h
	w.lastErr = ""
	w.state = "running"
	w.lastOK = time.Now().Unix()
	w.causeClass = "ok"
	w.lastRecoverOutcome = "ok"
	return nil
}

// Recover re-opens the WFP engine after transient close/failure.
func (w *WFPCtl) Recover() error {
	if w == nil {
		return nil
	}
	w.recoveries.Add(1)
	w.Stop()
	err := w.Start()
	if err == nil {
		w.lastRecoverOutcome = "recovered"
	} else if errors.Is(err, ErrControlPlaneTransient) {
		w.lastRecoverOutcome = "recover_failed_transient"
	} else {
		w.lastRecoverOutcome = "recover_failed_permanent"
	}
	return err
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
	w.state = "stopped"
}

// Health reports whether the WFP engine handle is active.
func (w *WFPCtl) Health() map[string]any {
	if w == nil {
		return map[string]any{"engine_open": false}
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	out := map[string]any{
		"engine_open":     w.h != 0,
		"state":           w.state,
		"start_attempts":  w.startAttempts.Load(),
		"start_failures":  w.startFailures.Load(),
		"recoveries":      w.recoveries.Load(),
	}
	if w.lastOK > 0 {
		out["last_ok_unix"] = w.lastOK
	}
	if w.lastErr != "" {
		out["last_error"] = w.lastErr
	}
	if w.causeClass != "" {
		out["cause_class"] = w.causeClass
	}
	if w.lastRecoverOutcome != "" {
		out["last_recover_outcome"] = w.lastRecoverOutcome
	}
	return out
}
