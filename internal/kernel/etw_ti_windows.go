//go:build windows

package kernel

import (
	"encoding/binary"
	"encoding/json"
	"path/filepath"
	"strings"
	"sync/atomic"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// tiCapability reports whether Kernel Threat Intelligence ETW providers can be
// enabled in this process (often restricted without PPL / vendor signing).
type tiCapability struct {
	probed atomic.Bool
	ok     atomic.Bool
	status atomic.Value // string
	reason atomic.Value // string
}

var threatIntelGUID = windows.GUID{
	Data1: 0xF4E1897C, Data2: 0xBB5D, Data3: 0x5668,
	Data4: [8]byte{0xF1, 0xD8, 0x04, 0x0F, 0x4D, 0x8D, 0xD3, 0x44},
}

var tiOpcodeNames = map[uint8]string{
	1: "AllocVM_Remote",
	2: "ProtectVM_Remote",
	3: "MapViewOfImage_Remote",
	4: "QueueUserAPC_Remote",
	5: "SetThreadContext_Remote",
	6: "WriteVM_Remote",
	7: "ReadVM_Remote",
	8: "CreateRemoteThread",
}

type TIEvent struct {
	Opcode      uint8
	CallerPID   uint32
	TargetPID   uint32
	BaseAddress uint64
	RegionSize  uint64
	Protect     uint32
	ThreadID    uint32
}

func (c *tiCapability) set(ok bool) {
	c.probed.Store(true)
	c.ok.Store(ok)
	if ok {
		c.status.Store("active_unprivileged")
		c.reason.Store("")
	}
}

func (c *tiCapability) enabled() bool {
	return c.probed.Load() && c.ok.Load()
}

func (c *tiCapability) skipThreatIntelProbe(reason string) {
	c.probed.Store(true)
	c.ok.Store(false)
	c.setStatus("disabled", reason)
}

func (c *tiCapability) setStatus(status, reason string) {
	c.status.Store(status)
	c.reason.Store(reason)
}

func (c *tiCapability) getStatus() (string, string) {
	s, _ := c.status.Load().(string)
	r, _ := c.reason.Load().(string)
	return s, r
}

func (d *ETWDriver) probeThreatIntelProviders() bool {
	if len(d.sessions) == 0 {
		d.tiCap.set(false)
		d.tiCap.setStatus("disabled", "no_etw_session")
		d.emitTIStatusEvent()
		return false
	}
	if err := enableSeDebugPrivilege(); err != nil {
		d.tiCap.setStatus("degraded_no_privilege", err.Error())
		d.emitTIStatusEvent()
		return false
	}
	if err := trySubscribeETWTI(d.sessions[0]); err == nil {
		d.tiCap.set(true)
		d.tiCap.setStatus("active_unprivileged", "")
		d.emitTIStatusEvent()
		return true
	}
	if err := ensureTIPPLService(); err == nil {
		d.tiCap.set(true)
		d.tiCap.setStatus("active_ppl", "")
		d.emitTIStatusEvent()
		return true
	}
	d.tiCap.set(false)
	d.tiCap.setStatus("degraded_subscription_failed", "ti provider enable failed")
	d.emitTIStatusEvent()
	return false
}

// ETW-TI Provider: Microsoft-Windows-Threat-Intelligence
// Full PPL (Protected Process Light) subscription requires:
//  1. An ELAM (Early Launch Anti-Malware) driver signed by Microsoft
//  2. Membership in Microsoft Virus Initiative (MVI)
//  3. WHQL signing of the ELAM driver
//  4. SERVICE_PROTECTED_ANTIMALWARE_LIGHT service type
//
// Fallback (implemented here): SeDebugPrivilege subscription
//   - Works on Windows 10/11 with admin + SeDebugPrivilege
//   - Does NOT receive all TI events (some opcodes PPL-only)
//   - Sufficient for development and testing
//
// Production path: integrate ELAM driver via etw_ti_service_windows.go
// once MVI membership and WHQL signing are obtained.
//
// G9 epic: runtime probing is gated by monitoring.etw_threat_intel (default false).
func enableSeDebugPrivilege() error {
	var tok windows.Token
	if err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_ADJUST_PRIVILEGES|windows.TOKEN_QUERY, &tok); err != nil {
		return err
	}
	defer tok.Close()
	var luid windows.LUID
	if err := windows.LookupPrivilegeValue(nil, windows.StringToUTF16Ptr("SeDebugPrivilege"), &luid); err != nil {
		return err
	}
	tp := windows.Tokenprivileges{
		PrivilegeCount: 1,
	}
	tp.Privileges[0].Luid = luid
	tp.Privileges[0].Attributes = windows.SE_PRIVILEGE_ENABLED
	if err := windows.AdjustTokenPrivileges(tok, false, &tp, 0, nil, nil); err != nil {
		return err
	}
	return nil
}

// ThreatIntelHealthSnapshot exposes L5 TI probing state for monitoring_health (L5 governance).
func (d *ETWDriver) ThreatIntelHealthSnapshot() ThreatIntelHealth {
	if d == nil {
		return ThreatIntelHealth{}
	}
	st, rsn := d.tiCap.getStatus()
	return ThreatIntelHealth{
		Probed: d.tiCap.probed.Load(),
		OK:     d.tiCap.ok.Load(),
		Status: st,
		Reason: rsn,
	}
}

func (d *ETWDriver) emitTIStatusEvent() {
	st, rsn := d.tiCap.getStatus()
	env := map[string]interface{}{
		"type":      "ti_status",
		"timestamp": time.Now().UTC(),
		"agent_id":  d.agentID,
		"status":    st,
		"reason":    rsn,
	}
	if d.buf != nil {
		if b, err := json.Marshal(env); err == nil {
			_ = d.buf.Write(b)
		}
	}
}

func trySubscribeETWTI(session *etwSession) error {
	if session == nil || session.sessionHandle == 0 {
		return windows.ERROR_INVALID_HANDLE
	}
	ret, _, _ := procEnableTraceEx2.Call(
		uintptr(session.sessionHandle),
		uintptr(unsafe.Pointer(&threatIntelGUID)),
		eventControlCodeEnableProvider,
		traceLevelVerbose,
		0xFFFFFFFFFFFFFFFF,
		0,
		0,
		0,
	)
	if ret != 0 {
		return windows.Errno(ret)
	}
	return nil
}

func decodeTIEvent(ud []byte, opcode uint8) *TIEvent {
	if len(ud) < 36 {
		return nil
	}
	return &TIEvent{
		Opcode:      opcode,
		CallerPID:   binary.LittleEndian.Uint32(ud[0:4]),
		TargetPID:   binary.LittleEndian.Uint32(ud[4:8]),
		BaseAddress: binary.LittleEndian.Uint64(ud[8:16]),
		RegionSize:  binary.LittleEndian.Uint64(ud[16:24]),
		Protect:     binary.LittleEndian.Uint32(ud[24:28]),
		ThreadID:    binary.LittleEndian.Uint32(ud[28:32]),
	}
}

func isRWXProtect(protect uint32) bool {
	return protect&0x40 != 0 || protect&0x80 != 0
}

func buildTIEnvelope(te TIEvent, callerName, targetName string) map[string]interface{} {
	technique := tiOpcodeNames[te.Opcode]
	if technique == "" {
		technique = "unknown"
	}
	env := map[string]interface{}{
		"type":           "injection",
		"source_pid":     te.CallerPID,
		"target_pid":     te.TargetPID,
		"source_process": callerName,
		"target_process": targetName,
		"target_image":   targetName,
		"technique":      technique,
		"address":        te.BaseAddress,
		"region_size":    te.RegionSize,
		"protect":        te.Protect,
		"thread_id":      te.ThreadID,
	}
	if strings.EqualFold(targetName, "lsass.exe") {
		env["type"] = "credential_access"
		env["technique"] = "lsass_" + technique
		env["access_mask"] = te.Protect
		env["severity"] = "P0"
	}
	if te.Opcode == 2 && isRWXProtect(te.Protect) {
		env["type"] = "memory"
		env["operation"] = "rwx_alloc"
	}
	return env
}

func resolveProcessName(pid uint32) string {
	if pid == 0 {
		return ""
	}
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return ""
	}
	defer windows.CloseHandle(h)
	buf := make([]uint16, windows.MAX_PATH)
	size := uint32(len(buf))
	if err := windows.QueryFullProcessImageName(h, 0, &buf[0], &size); err != nil {
		return ""
	}
	return filepath.Base(strings.ToLower(windows.UTF16ToString(buf[:size])))
}
