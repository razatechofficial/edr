//go:build windows

package kernel

import (
	"encoding/hex"
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

	lastMirrorSendUnix    int64
	lastMirrorSendBytes   uint64
	lastMirrorSendOutcome string
	lastMirrorSendErr     string
	lastMirrorFramePrefix string // hex of first 16 bytes for diagnostics
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

// SendMirror is diagnostics-only: it builds the same length-prefixed control frame
// as the minifilter path (see BuildControlPlaneWire) and records health metrics.
// It does not send bytes to a kernel driver or WFP callout; the user-mode Fwpm
// engine session does not accept arbitrary IOCTL-style payloads.
//
// Health outcomes:
//   - "framed-only" — frame built successfully while the engine handle was open.
//   - "framed-no-channel" — engine handle was not open (no framing performed).
//   - "encode_error" — wire framing failed.
func (w *WFPCtl) SendMirror(cmd ControlPlaneCommand, payload []byte) error {
	if w == nil {
		return ErrWFPNotAvailable
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.h == 0 {
		w.recordMirrorSend(0, "", "framed-no-channel", ErrWFPNotAvailable)
		return ErrWFPNotAvailable
	}
	wire, err := BuildControlPlaneWire(cmd, payload)
	if err != nil {
		w.recordMirrorSend(0, "", "encode_error", err)
		return err
	}
	prefix := ""
	if len(wire) > 0 {
		n := 16
		if len(wire) < n {
			n = len(wire)
		}
		prefix = hex.EncodeToString(wire[:n])
	}
	w.recordMirrorSend(uint64(len(wire)), prefix, "framed-only", nil)
	return nil
}

func (w *WFPCtl) recordMirrorSend(n uint64, framePrefix, outcome string, sendErr error) {
	w.lastMirrorSendUnix = time.Now().Unix()
	w.lastMirrorSendBytes = n
	w.lastMirrorSendOutcome = outcome
	w.lastMirrorSendErr = ""
	if sendErr != nil {
		w.lastMirrorSendErr = sendErr.Error()
	}
	w.lastMirrorFramePrefix = framePrefix
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
	if w.lastMirrorSendUnix > 0 {
		out["last_mirror_send_unix"] = w.lastMirrorSendUnix
		out["last_mirror_send_bytes"] = w.lastMirrorSendBytes
		out["last_mirror_send_outcome"] = w.lastMirrorSendOutcome
		if w.lastMirrorSendErr != "" {
			out["last_mirror_send_error"] = w.lastMirrorSendErr
		}
		if w.lastMirrorFramePrefix != "" {
			out["last_mirror_frame_prefix_hex"] = w.lastMirrorFramePrefix
		}
	}
	return out
}
