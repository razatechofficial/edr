//go:build windows

package kernel

// decodeKernelRegistry maps Microsoft-Windows-Kernel-Registry payloads into
// envelope fields consumed by MapKernelJSONToTelemetry. The provider emits
// realtime CreateKey/OpenKey/DeleteKey/SetValue/DeleteValue events with the
// hive-relative key path appended as a UTF-16LE string. Layout (x64):
//
//	uint32 Status        @0
//	uint64 KeyHandle     @4
//	uint64 KeyObject     @12
//	uint32 ProcessId     @20
//	utf16le KeyName      @24
//
// Older builds may pad differently; the decoder probes the most common
// offsets and falls back to extracting the first non-empty UTF-16 string.
func (d *ETWDriver) decodeKernelRegistry(record *etwEventRecord, env map[string]interface{}) {
	ud := userDataSlice(record)
	if ud == nil {
		return
	}
	env["operation"] = registryOpcodeName(record.EventHeader.EventDescriptor.Opcode)

	if len(ud) >= 24 {
		// PID at offset 20 in the canonical x64 layout.
		env["pid"] = uint32FromLE(ud[20:24])
	}
	if len(ud) > 24 {
		if name := extractUTF16String(ud[24:]); name != "" {
			env["key_path"] = name
			env["path"] = name
		}
		return
	}
	if name := extractUTF16String(ud); name != "" {
		env["key_path"] = name
		env["path"] = name
	}
}

// registryOpcodeName maps Kernel-Registry opcodes to operation strings used by
// the detection layer. Codes from Microsoft-Windows-Kernel-Registry manifest:
//
//	1 CreateKey, 2 OpenKey, 3 DeleteKey, 4 QueryKey,
//	5 SetValueKey, 6 DeleteValueKey, 7 QueryValueKey,
//	8 EnumerateKey, 9 EnumerateValueKey, 10 QueryMultipleValueKey,
//	11 SetInformationKey, 12 FlushKey, 13 KCBCreate, 14 KCBDelete,
//	15 KCBRundownBegin, 16 KCBRundownEnd, 17 Virtualize, 18 CloseKey,
//	19 SetSecurityDescriptor, 20 QuerySecurityDescriptor.
func registryOpcodeName(op uint8) string {
	switch op {
	case 1:
		return "create_key"
	case 2:
		return "open_key"
	case 3:
		return "delete_key"
	case 4:
		return "query_key"
	case 5:
		return "set_value"
	case 6:
		return "delete_value"
	case 7:
		return "query_value"
	case 8:
		return "enumerate_key"
	case 9:
		return "enumerate_value"
	case 11:
		return "set_information"
	case 12:
		return "flush"
	case 18:
		return "close_key"
	case 19:
		return "set_security"
	case 20:
		return "query_security"
	}
	return "event"
}

func uint32FromLE(b []byte) uint32 {
	if len(b) < 4 {
		return 0
	}
	return uint32(b[0]) | uint32(b[1])<<8 | uint32(b[2])<<16 | uint32(b[3])<<24
}
