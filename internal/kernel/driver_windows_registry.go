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
	opcode := record.EventHeader.EventDescriptor.Opcode
	env["operation"] = registryOpcodeName(opcode)

	if len(ud) >= 24 {
		// PID at offset 20 in the canonical x64 layout.
		env["pid"] = uint32FromLE(ud[20:24])
	}

	// P2-2: SetValueKey (opcode 5) carries the value name and value
	// data after the key path. The canonical Microsoft layout is:
	//
	//   ...header (24 bytes)...
	//   utf16le KeyName (NUL-terminated)
	//   utf16le ValueName (NUL-terminated)
	//   uint32  DataType
	//   uint32  DataSize
	//   bytes   Data (DataSize bytes)
	//
	// Decoder is best-effort — older provider versions sometimes elide
	// fields. Bail out at the first failure and keep what we got.
	if opcode == 5 && len(ud) > 24 {
		offset := 24
		key, consumed := extractUTF16StringBounded(ud[offset:], 32768)
		if key != "" {
			env["key_path"] = key
			env["path"] = key
		}
		offset += consumed
		if offset >= len(ud) {
			return
		}
		valName, consumedV := extractUTF16StringBounded(ud[offset:], 1024)
		if valName != "" {
			env["value_name"] = valName
		}
		offset += consumedV
		if offset+8 > len(ud) {
			return
		}
		dataType := uint32FromLE(ud[offset : offset+4])
		dataSize := uint32FromLE(ud[offset+4 : offset+8])
		offset += 8
		env["value_type"] = registryValueTypeName(dataType)
		if dataSize == 0 || offset+int(dataSize) > len(ud) {
			return
		}
		raw := ud[offset : offset+int(dataSize)]
		env["new_data"] = registryValueDataString(dataType, raw)
		return
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

// registryValueTypeName maps REG_* constants to readable strings.
func registryValueTypeName(t uint32) string {
	switch t {
	case 0:
		return "REG_NONE"
	case 1:
		return "REG_SZ"
	case 2:
		return "REG_EXPAND_SZ"
	case 3:
		return "REG_BINARY"
	case 4:
		return "REG_DWORD"
	case 5:
		return "REG_DWORD_BIG_ENDIAN"
	case 6:
		return "REG_LINK"
	case 7:
		return "REG_MULTI_SZ"
	case 11:
		return "REG_QWORD"
	}
	return ""
}

// registryValueDataString renders a registry value payload as a UTF-8
// string suitable for an EDR alert. REG_SZ / REG_EXPAND_SZ / REG_LINK
// are decoded as UTF-16LE; REG_DWORD / REG_QWORD as decimal; everything
// else is hex-encoded (binary, multi-sz are likely to contain NULs).
// The output is capped at 4 KiB so a malicious actor cannot blow up
// the event with multi-megabyte registry values.
func registryValueDataString(dataType uint32, raw []byte) string {
	const cap = 4 * 1024
	switch dataType {
	case 1, 2, 6: // REG_SZ, REG_EXPAND_SZ, REG_LINK
		s := extractUTF16String(raw)
		if len(s) > cap {
			s = s[:cap]
		}
		return s
	case 4: // REG_DWORD
		if len(raw) >= 4 {
			return uintToString(uint64(uint32FromLE(raw[:4])))
		}
	case 11: // REG_QWORD
		if len(raw) >= 8 {
			var v uint64
			for i := 0; i < 8; i++ {
				v |= uint64(raw[i]) << (8 * i)
			}
			return uintToString(v)
		}
	}
	if len(raw) > cap {
		raw = raw[:cap]
	}
	return hexEncodeBytes(raw)
}

func uintToString(v uint64) string {
	if v == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for v > 0 {
		i--
		buf[i] = byte('0' + v%10)
		v /= 10
	}
	return string(buf[i:])
}

func hexEncodeBytes(b []byte) string {
	if len(b) == 0 {
		return ""
	}
	const hex = "0123456789abcdef"
	out := make([]byte, len(b)*2)
	for i, c := range b {
		out[i*2] = hex[c>>4]
		out[i*2+1] = hex[c&0xf]
	}
	return string(out)
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
