//go:build windows

package kernel

// decodeKernelRegistry maps Microsoft-Windows-Kernel-Registry payloads into
// envelope fields consumed by MapKernelJSONToTelemetry.
//
// The templates below were read off hex dumps of real records taken on a
// hosted windows-latest runner, because the layout this decoder used to assume
//
//	uint32 Status @0, uint64 KeyHandle @4, uint64 KeyObject @12,
//	uint32 ProcessId @20, utf16le KeyName @24
//
// is the NT Kernel Logger Registry_TypeGroup1 MOF layout, not this provider's.
// The practical consequences were that the pid was read from the middle of a
// pointer, and that the SetValueKey value name came out two bytes into the
// string ("itest_value" decoded as "test_value").
//
// CreateKey (1) and OpenKey (2), measured, length 156 for a long key:
//
//	@0  u64   BaseObject      (the parent key)
//	@8  u64   KeyObject       (the key this event is about)
//	@16 u32   Status
//	@20 u32   Disposition
//	@24 utf16 BaseName        (empty in every record observed)
//	    utf16 RelativeName    ("Software\Microsoft\Windows\...")
//
// SetValueKey (5), measured, length 88:
//
//	@0  u64   KeyObject
//	@8  u32   Status
//	@12 u32   Type            (REG_* of the value being written)
//	@16 u32   DataSize
//	@20 utf16 KeyName         (empty in every record observed)
//	    utf16 ValueName       ("QuietHoursTelemetryLastRun")
//	    u16   CapturedDataSize, then that many bytes of data
//
// Note what SetValueKey does *not* carry: the key's path. Only CreateKey and
// OpenKey name a key; everything afterwards identifies it by the KeyObject
// pointer. So the create/open events seed a KeyObject to path cache and the
// mutating events resolve against it. Without that, the events an operator
// actually cares about — a value being written — have no path at all.
//
// The remaining event ids' templates were not verified against a real record.
// They fall through to a bounded scan for the first plausible UTF-16 string,
// which is what the whole decoder used to do, and the comment says so rather
// than implying a layout this code has checked.
func (d *ETWDriver) decodeKernelRegistry(record *etwEventRecord, env map[string]interface{}) {
	ud := userDataSlice(record)
	if ud == nil {
		return
	}
	eventID := record.EventHeader.EventDescriptor.Id
	env["operation"] = registryOperationName(eventID)

	// The PID comes from the event header, which every ETW record carries
	// and which needs no knowledge of the payload template.
	if pid := record.EventHeader.ProcessId; pid != 0 {
		env["pid"] = pid
	}

	setKeyPath := func(p string) {
		if p == "" {
			return
		}
		env["key_path"] = p
		env["path"] = p
	}

	switch eventID {
	case kernelRegistryEvtCreateKey, kernelRegistryEvtOpenKey:
		if len(ud) < 26 {
			break
		}
		baseObject := uint64FromLE(ud[0:8])
		keyObject := uint64FromLE(ud[8:16])
		env["key_object"] = keyObject
		base, consumed := extractUTF16StringBounded(ud[24:], 32768)
		rel := ""
		if off := 24 + consumed; off < len(ud) {
			rel, _ = extractUTF16StringBounded(ud[off:], 32768)
		}
		full := registryJoinKeyPath(base, rel)
		if full == "" {
			// A relative name under a key we have already seen.
			full = d.regKeyLookup(baseObject)
		} else if base == "" && baseObject != 0 {
			if parent := d.regKeyLookup(baseObject); parent != "" {
				full = registryJoinKeyPath(parent, rel)
			}
		}
		setKeyPath(full)
		d.regKeyRemember(keyObject, full)
		return

	case kernelRegistryEvtSetValue:
		if len(ud) < 22 {
			break
		}
		keyObject := uint64FromLE(ud[0:8])
		env["key_object"] = keyObject
		env["value_type"] = registryValueTypeName(uint32FromLE(ud[12:16]))
		dataSize := int(uint32FromLE(ud[16:20]))

		keyName, consumed := extractUTF16StringBounded(ud[20:], 32768)
		offset := 20 + consumed
		valName := ""
		if offset < len(ud) {
			var consumedV int
			valName, consumedV = extractUTF16StringBounded(ud[offset:], 1024)
			offset += consumedV
		}
		if valName != "" {
			env["value_name"] = valName
		}
		// KeyName is relative to KeyObject, and empty on every record
		// observed; the path comes from the create/open cache.
		setKeyPath(registryJoinKeyPath(d.regKeyLookup(keyObject), keyName))

		// CapturedDataSize is a u16, and is not DataSize: the provider
		// truncates large values.
		if offset+2 > len(ud) {
			return
		}
		captured := int(uint32FromLE([]byte{ud[offset], ud[offset+1], 0, 0}))
		offset += 2
		if captured > dataSize && dataSize > 0 {
			captured = dataSize
		}
		if captured <= 0 || offset+captured > len(ud) {
			return
		}
		env["new_data"] = registryValueDataString(uint32FromLE(ud[12:16]), ud[offset:offset+captured])
		return

	case kernelRegistryEvtDeleteKey, kernelRegistryEvtDeleteValue,
		kernelRegistryEvtSetInformation, kernelRegistryEvtCloseKey:
		if len(ud) >= 8 {
			keyObject := uint64FromLE(ud[0:8])
			env["key_object"] = keyObject
			setKeyPath(d.regKeyLookup(keyObject))
			if eventID == kernelRegistryEvtCloseKey {
				return
			}
		}
	}

	// Unverified templates: scan for the first plausible UTF-16 string
	// rather than claim an offset.
	if len(ud) > 24 {
		if name := extractUTF16String(ud[24:]); name != "" {
			setKeyPath(name)
			return
		}
	}
	if name := extractUTF16String(ud); name != "" {
		setKeyPath(name)
	}
}

// registryJoinKeyPath joins a base key path and a relative name with a single
// backslash, tolerating either being empty.
func registryJoinKeyPath(base, rel string) string {
	switch {
	case base == "":
		return rel
	case rel == "":
		return base
	}
	if base[len(base)-1] == '\\' {
		return base + rel
	}
	return base + "\\" + rel
}

// regKeyRemember records a KeyObject's resolved path, bounded FIFO.
func (d *ETWDriver) regKeyRemember(keyObject uint64, path string) {
	if keyObject == 0 || path == "" {
		return
	}
	d.regKeyMu.Lock()
	defer d.regKeyMu.Unlock()
	if d.regKeyPath == nil {
		d.regKeyPath = make(map[uint64]string)
	}
	capN := d.regKeyCap
	if capN <= 0 {
		capN = 65536
	}
	if _, exists := d.regKeyPath[keyObject]; !exists {
		d.regKeyFIFO = append(d.regKeyFIFO, keyObject)
		for len(d.regKeyFIFO) > capN {
			old := d.regKeyFIFO[0]
			d.regKeyFIFO = d.regKeyFIFO[1:]
			delete(d.regKeyPath, old)
		}
	}
	d.regKeyPath[keyObject] = path
}

func (d *ETWDriver) regKeyLookup(keyObject uint64) string {
	if keyObject == 0 {
		return ""
	}
	d.regKeyMu.RLock()
	defer d.regKeyMu.RUnlock()
	return d.regKeyPath[keyObject]
}

func uint64FromLE(b []byte) uint64 {
	if len(b) < 8 {
		return 0
	}
	return uint64(b[0]) | uint64(b[1])<<8 | uint64(b[2])<<16 | uint64(b[3])<<24 |
		uint64(b[4])<<32 | uint64(b[5])<<40 | uint64(b[6])<<48 | uint64(b[7])<<56
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

// Microsoft-Windows-Kernel-Registry event ids. Measured on a hosted
// windows-latest runner over 25 seconds of ordinary activity, which produced
// the expected shape of a registry workload: OpenKey 8107, QueryValueKey 6299,
// CloseKey 4099, QueryKey 1943, EnumerateKey 936, EnumerateValueKey 614,
// SetValueKey 71, CreateKey 32, SetInformationKey 22.
//
// The provider sets Opcode to the event id plus 31, which is why this decoder
// found nothing: it switched on the opcode against these numbers, so every
// event's operation came out as the fallback "event" string and the SetValueKey
// branch -- the one that extracts the value name, type and data, the whole
// point of watching the registry -- never ran once.
const (
	kernelRegistryEvtCreateKey      uint16 = 1
	kernelRegistryEvtOpenKey        uint16 = 2
	kernelRegistryEvtDeleteKey      uint16 = 3
	kernelRegistryEvtSetValue       uint16 = 5
	kernelRegistryEvtDeleteValue    uint16 = 6
	kernelRegistryEvtSetInformation uint16 = 11
	kernelRegistryEvtCloseKey       uint16 = 13
)

// registryOperationName maps Kernel-Registry event ids to operation strings used by
// the detection layer. Codes from Microsoft-Windows-Kernel-Registry manifest:
//
//	1 CreateKey, 2 OpenKey, 3 DeleteKey, 4 QueryKey,
//	5 SetValueKey, 6 DeleteValueKey, 7 QueryValueKey,
//	8 EnumerateKey, 9 EnumerateValueKey, 10 QueryMultipleValueKey,
//	11 SetInformationKey, 12 FlushKey, 13 KCBCreate, 14 KCBDelete,
//	15 KCBRundownBegin, 16 KCBRundownEnd, 17 Virtualize, 18 CloseKey,
//	19 SetSecurityDescriptor, 20 QuerySecurityDescriptor.
func registryOperationName(eventID uint16) string {
	switch eventID {
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
	case kernelRegistryEvtCloseKey:
		return "close_key"
	}
	// SetSecurityKey and QuerySecurityKey exist in the manifest; their ids
	// were not observed on the measured runner and are deliberately not
	// guessed here, so they fall through to the generic label rather than
	// being given a name that might belong to another event.
	return "event"
}

func uint32FromLE(b []byte) uint32 {
	if len(b) < 4 {
		return 0
	}
	return uint32(b[0]) | uint32(b[1])<<8 | uint32(b[2])<<16 | uint32(b[3])<<24
}
