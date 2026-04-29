//go:build windows

package kernel

// decodeDNSClient maps Microsoft-Windows-DNS-Client ETW payloads into envelope
// fields consumed by MapKernelJSONToTelemetry. The payload starts with a
// UTF-16LE QueryName followed by uint32 QueryType and uint64 QueryOptions.
//
// Event IDs handled (manifest):
//
//	3006 DnsClient_QuerySent
//	3008 DnsClient_QueryResponseSuccess
//	3009 DnsClient_QueryResponseNoData
//	3010 DnsClient_QueryFailure
//	3011 DnsClient_QueryError
//	3018 DnsClient_QueryCompleted
//	3020 DnsClient_RecordReceived
func (d *ETWDriver) decodeDNSClient(record *etwEventRecord, env map[string]interface{}) {
	ud := userDataSlice(record)
	if ud == nil {
		return
	}
	eid := record.EventHeader.EventDescriptor.Id
	switch eid {
	case 3006, 3008, 3009, 3010, 3011, 3018, 3020:
		q := extractUTF16String(ud)
		if q != "" {
			env["query"] = q
			env["domain"] = q
			// QueryType lives just after the UTF-16LE name terminator.
			off := utf16StringEnd(ud)
			if off > 0 && len(ud) >= off+4 {
				env["query_type"] = uint32FromLE(ud[off : off+4])
			}
		}
		switch eid {
		case 3010, 3011:
			env["dns_outcome"] = "error"
		case 3009:
			env["dns_outcome"] = "no_data"
		default:
			env["dns_outcome"] = "ok"
		}
	}
}
