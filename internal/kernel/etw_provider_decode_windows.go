//go:build windows

package kernel

import (
	"encoding/binary"
	"fmt"
	"strings"
)

// decodeStructuredETW fills envelope with provider-specific fields when user data
// matches a known layout; unknown layouts still get a short hex prefix for triage.
func (d *ETWDriver) decodeStructuredETW(record *etwEventRecord, env map[string]interface{}) {
	ud := userDataSlice(record)
	if ud == nil {
		return
	}
	env["etw_user_data_len"] = len(ud)
	if len(ud) >= 4 {
		n := 64
		if len(ud) < n {
			n = len(ud)
		}
		env["etw_user_data_prefix_hex"] = fmt.Sprintf("%x", ud[:n])
	}

	pid := record.EventHeader.ProviderId
	eid := record.EventHeader.EventDescriptor.Id

	switch pid {
	case amsiGUID:
		decodeAMSIETW(eid, ud, env)
	case codeIntegrityGUID:
		decodeCodeIntegrityETW(eid, ud, env)
	case appLockerGUID:
		decodeAppLockerETW(eid, ud, env)
	case defenderETWGUID:
		decodeDefenderETW(eid, ud, env)
	case threatIntelGUID:
		d.decodeThreatIntelETW(record, env)
	case wmiActivityGUID:
		decodeWMIEtw(eid, ud, env)
	case powershellGUID:
		decodePowerShellEtw(eid, ud, env)
	case bitsClientGUID:
		decodeBITSEtw(eid, ud, env)
	case taskSchedulerGUID:
		decodeTaskSchedulerEtw(eid, ud, env)
	case kernelObjectGUID:
		// Pipe events: keep prefix_hex; optional first string if present.
		if s := extractUTF16String(ud); s != "" {
			env["path"] = s
		}
	}
}

func (d *ETWDriver) decodeThreatIntelETW(record *etwEventRecord, env map[string]interface{}) {
	ud := userDataSlice(record)
	if ud == nil {
		return
	}
	te := decodeTIEvent(ud, record.EventHeader.EventDescriptor.Opcode)
	if te == nil {
		return
	}
	technique := tiOpcodeNames[te.Opcode]
	if technique == "" {
		technique = fmt.Sprintf("opcode_%d", te.Opcode)
	}
	callerName := resolveProcessName(te.CallerPID)
	targetName := resolveProcessName(te.TargetPID)
	base := buildTIEnvelope(*te, callerName, targetName)
	if technique != "unknown" && !strings.HasPrefix(fmt.Sprintf("%v", base["technique"]), "lsass_") {
		base["technique"] = technique
	}
	for k, v := range base {
		env[k] = v
	}
}

func decodeWMIEtw(eventID uint16, ud []byte, env map[string]interface{}) {
	// 5860/5861: binary layout varies by OS; consume leading GUID-style bytes then strings.
	off := 0
	if len(ud) >= 16 {
		off = 16
	}
	s := extractUTF16String(ud[off:])
	if s != "" {
		env["message"] = s
	}
	if s2 := extractUTF16StringAfter(ud[off:], s); s2 != "" {
		env["query"] = s2
	}
	env["wmi_event_id"] = eventID
}

func decodePowerShellEtw(eventID uint16, ud []byte, env map[string]interface{}) {
	if eventID != 4104 && eventID != 4103 {
		return
	}
	// Common 4104 layout: two uint32 counters then wide script block text.
	if len(ud) >= 8 {
		if s := extractUTF16String(ud[8:]); s != "" {
			env["script_block"] = s
			env["message"] = s
			return
		}
	}
	if s := extractUTF16String(ud); s != "" {
		env["script_block"] = s
		env["message"] = s
	}
}

func decodeBITSEtw(eventID uint16, ud []byte, env map[string]interface{}) {
	env["bits_event_id"] = eventID
	first := extractUTF16String(ud)
	if first != "" {
		env["path"] = first
	}
	if len(ud) >= 4 {
		if s2 := extractUTF16String(ud[4:]); s2 != "" && s2 != first {
			env["url"] = s2
		}
	}
}

func decodeAMSIETW(eventID uint16, ud []byte, env map[string]interface{}) {
	env["etw_security_subprovider"] = "amsi"
	env["amsi_event_id"] = eventID
	first := extractUTF16String(ud)
	if first != "" {
		env["message"] = first
		env["content"] = first
	}
	if s2 := extractUTF16StringAfter(ud, first); s2 != "" {
		env["app_name"] = s2
	}
}

func decodeCodeIntegrityETW(eventID uint16, ud []byte, env map[string]interface{}) {
	env["etw_security_subprovider"] = "code_integrity"
	env["ci_event_id"] = eventID
	if s := extractUTF16String(ud); s != "" {
		env["message"] = s
		env["path"] = s
	}
}

func decodeAppLockerETW(eventID uint16, ud []byte, env map[string]interface{}) {
	env["etw_security_subprovider"] = "applocker"
	env["applocker_event_id"] = eventID
	first := extractUTF16String(ud)
	if first != "" {
		env["path"] = first
		env["message"] = first
	}
	if s2 := extractUTF16StringAfter(ud, first); s2 != "" {
		env["rule_id"] = s2
	}
}

func decodeDefenderETW(eventID uint16, ud []byte, env map[string]interface{}) {
	env["etw_security_subprovider"] = "defender"
	env["defender_event_id"] = eventID
	first := extractUTF16String(ud)
	if first != "" {
		env["message"] = first
	}
	if s2 := extractUTF16StringAfter(ud, first); s2 != "" {
		env["threat_name"] = s2
	}
}

func decodeTaskSchedulerEtw(eventID uint16, ud []byte, env map[string]interface{}) {
	env["task_event_id"] = eventID
	switch eventID {
	case 106, 140, 141:
		if s := extractUTF16String(ud); s != "" {
			env["task_name"] = s
			env["message"] = s
		}
		if len(ud) > 8 {
			if s2 := extractUTF16String(ud[8:]); s2 != "" {
				env["task_action"] = s2
			}
		}
	default:
		if s := extractUTF16String(ud); s != "" {
			env["message"] = s
		}
	}
}

func extractUTF16StringAfter(ud []byte, skipPrefix string) string {
	if skipPrefix == "" {
		return ""
	}
	// Advance past first UTF-16 string including terminator.
	idx := utf16StringEnd(ud)
	if idx < 0 || idx >= len(ud) {
		return ""
	}
	return extractUTF16String(ud[idx:])
}

func utf16StringEnd(b []byte) int {
	if len(b) < 2 {
		return -1
	}
	n := len(b) / 2
	for i := 0; i < n; i++ {
		c := binary.LittleEndian.Uint16(b[i*2:])
		if c == 0 {
			return (i + 1) * 2
		}
	}
	return len(b)
}
