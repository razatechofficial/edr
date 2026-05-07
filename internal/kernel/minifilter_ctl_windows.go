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

func classifyFilterPortHR(hr uint32) (causeClass string, err error) {
	switch hr {
	case 0x800706BA, 0x800706BE, 0x800706BF, 0x80010100: // RPC_S_* / RPC_E_SYS_CALL_FAILED
		return "transient", fmt.Errorf("%w: HRESULT_%08x", ErrControlPlaneTransient, hr)
	case 0x80070002, 0xC0000034:
		return "permanent", fmt.Errorf("%w: HRESULT_%08x", ErrMinifilterDriverNotPresent, hr)
	default:
		return "permanent", fmt.Errorf("%w: HRESULT_%08x", ErrMinifilterDriverNotPresent, hr)
	}
}

var (
	modFltLib                          = windows.NewLazySystemDLL("fltlib.dll")
	procFilterConnectCommunicationPort = modFltLib.NewProc("FilterConnectCommunicationPort")
	procFilterSendMessage              = modFltLib.NewProc("FilterSendMessage")
)

// filterSendMessageFn is swappable in unit tests.
var filterSendMessageFn = func(hPort windows.Handle, inBuf uintptr, inLen uintptr, outBuf uintptr, outLen uintptr, bytesReturned uintptr) uintptr {
	modFltLib.Load()
	r0, _, _ := procFilterSendMessage.Call(
		uintptr(hPort),
		inBuf,
		inLen,
		outBuf,
		outLen,
		bytesReturned,
	)
	return r0
}

// MinifilterCtl maintains a user-mode handle to a minifilter communication port.
// When no port name is configured, Start is a no-op and Health reports skipped.
type MinifilterCtl struct {
	mu sync.Mutex

	portUTF16 *uint16
	h         windows.Handle
	lastErr   string
	state     string
	lastOK    int64

	startAttempts atomic.Uint64
	startFailures atomic.Uint64
	recoveries    atomic.Uint64

	causeClass         string
	lastRecoverOutcome string

	lastSendUnix    int64
	lastSendBytes   uint64
	lastSendOutcome string
	lastSendErr     string
}

// NewMinifilterCtl prepares a control handle for the given port name (e.g. "\\EdrPort").
func NewMinifilterCtl(portName string) *MinifilterCtl {
	if portName == "" {
		return &MinifilterCtl{state: "skipped"}
	}
	u, err := windows.UTF16PtrFromString(portName)
	if err != nil {
		return &MinifilterCtl{lastErr: err.Error(), state: "error"}
	}
	return &MinifilterCtl{portUTF16: u, state: "init"}
}

// Start connects to the minifilter communication port.
func (m *MinifilterCtl) Start() error {
	if m == nil || m.portUTF16 == nil {
		return nil
	}
	m.startAttempts.Add(1)
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.h != 0 {
		m.state = "running"
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
		hr := uint32(r0)
		cc, werr := classifyFilterPortHR(hr)
		m.lastErr = fmt.Sprintf("HRESULT_%08x", hr)
		m.state = "degraded"
		m.startFailures.Add(1)
		m.causeClass = cc
		m.lastRecoverOutcome = "start_failed"
		return werr
	}
	if h == 0 {
		m.lastErr = "zero_handle"
		m.state = "degraded"
		m.startFailures.Add(1)
		m.causeClass = "permanent"
		m.lastRecoverOutcome = "start_failed"
		return ErrMinifilterDriverNotPresent
	}
	m.h = h
	m.lastErr = ""
	m.state = "running"
	m.lastOK = time.Now().Unix()
	m.causeClass = "ok"
	m.lastRecoverOutcome = "ok"
	return nil
}

// Recover re-attempts minifilter port connectivity after a degraded state.
func (m *MinifilterCtl) Recover() error {
	if m == nil || m.portUTF16 == nil {
		return nil
	}
	m.recoveries.Add(1)
	m.Stop()
	err := m.Start()
	if err == nil {
		m.lastRecoverOutcome = "recovered"
	} else if errors.Is(err, ErrControlPlaneTransient) {
		m.lastRecoverOutcome = "recover_failed_transient"
	} else {
		m.lastRecoverOutcome = "recover_failed_permanent"
	}
	return err
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
	if m.portUTF16 == nil {
		m.state = "skipped"
	} else {
		m.state = "stopped"
	}
}

func (m *MinifilterCtl) recordSendHealth(n int, outcome string, sendErr error) {
	m.lastSendUnix = time.Now().Unix()
	m.lastSendBytes = uint64(n)
	m.lastSendOutcome = outcome
	m.lastSendErr = ""
	if sendErr != nil {
		m.lastSendErr = sendErr.Error()
	}
}

// Send frames a typed control message and delivers it via FilterSendMessage.
func (m *MinifilterCtl) Send(cmd ControlPlaneCommand, payload []byte) error {
	if m == nil || m.portUTF16 == nil {
		return ErrMinifilterDriverNotPresent
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.h == 0 {
		m.recordSendHealth(0, "not_connected", ErrMinifilterDriverNotPresent)
		return ErrMinifilterDriverNotPresent
	}
	wire, err := BuildControlPlaneWire(cmd, payload)
	if err != nil {
		m.recordSendHealth(0, "encode_error", err)
		return err
	}
	var bytesReturned uint32
	r0 := filterSendMessageFn(
		m.h,
		uintptr(unsafe.Pointer(&wire[0])),
		uintptr(len(wire)),
		0,
		0,
		uintptr(unsafe.Pointer(&bytesReturned)),
	)
	if r0 != 0 {
		hr := uint32(r0)
		_, werr := classifyFilterPortHR(hr)
		m.recordSendHealth(len(wire), "send_failed", werr)
		return werr
	}
	m.recordSendHealth(len(wire), "ok", nil)
	return nil
}

// Health returns attachment status for monitoring_health.json.
func (m *MinifilterCtl) Health() map[string]any {
	if m == nil {
		return map[string]any{"connected": false}
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.portUTF16 == nil && m.lastErr == "" {
		return map[string]any{
			"connected": false,
			"skipped":   true,
			"state":     "skipped",
		}
	}
	out := map[string]any{
		"connected":      m.h != 0,
		"state":          m.state,
		"start_attempts": m.startAttempts.Load(),
		"start_failures": m.startFailures.Load(),
		"recoveries":     m.recoveries.Load(),
	}
	if m.lastOK > 0 {
		out["last_ok_unix"] = m.lastOK
	}
	if m.lastErr != "" {
		out["last_error"] = m.lastErr
	}
	if m.causeClass != "" {
		out["cause_class"] = m.causeClass
	}
	if m.lastRecoverOutcome != "" {
		out["last_recover_outcome"] = m.lastRecoverOutcome
	}
	if m.lastSendUnix > 0 {
		out["last_send_unix"] = m.lastSendUnix
		out["last_send_bytes"] = m.lastSendBytes
		out["last_send_outcome"] = m.lastSendOutcome
		if m.lastSendErr != "" {
			out["last_send_error"] = m.lastSendErr
		}
	}
	return out
}
