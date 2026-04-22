//go:build windows

package kernel

// decodeDNSClient maps Microsoft-Windows-DNS-Client ETW payloads into envelope fields
// consumed by MapKernelJSONToTelemetry (query / domain).
func (d *ETWDriver) decodeDNSClient(record *etwEventRecord, env map[string]interface{}) {
	ud := userDataSlice(record)
	if ud == nil {
		return
	}
	switch record.EventHeader.EventDescriptor.Id {
	case 3006, 3008, 3009:
		if q := extractUTF16String(ud); q != "" {
			env["query"] = q
			env["domain"] = q
		}
	}
}
