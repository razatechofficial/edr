//go:build darwin

package kernel

// esfOperationByType maps raw ESF event type integers to Sigma event.action
// strings when the C esfOperationName switch returns unknown (newer SDK types).
//
// The values are the es_event_type_t ordinals from
// <EndpointSecurity/ESTypes.h>. Apple only appends to that enum, so an ordinal
// is stable once it ships; what is not safe is writing one from memory, which
// is how this table came to have every entry wrong. It previously said
// setuid=24 and setgid=25 (24 is NOTIFY_IOKIT_OPEN), cs_invalidated=62
// (NOTIFY_FCNTL), xpc_connect=65 (NOTIFY_LISTEXTATTR), malware 112/113
// (NOTIFY_AUTHENTICATION and XP_MALWARE_DETECTED) and tcc_modify=147
// (XPC_CONNECT). The practical effects: the credential_change capability row
// could never be credited, and an XPC connection was reported as a TCC privacy
// authorization, because driver_darwin.go routes anything this table calls
// "tcc_modify" into a privacy event.
//
// These were read out of the SDK header rather than recalled:
//
//	awk over the es_event_type_t enum in
//	$(xcrun --show-sdk-path)/usr/include/EndpointSecurity/ESTypes.h
var esfOperationByType = map[int]string{
	96:  "cs_invalidated",
	105: "setuid",
	106: "setgid",
	107: "seteuid",
	108: "setegid",
	109: "setreuid",
	110: "setregid",
	114: "xp_malware_detected",
	115: "xp_malware_remediated",
	120: "screensharing_attach",
	121: "screensharing_detach",
	147: "xpc_connect",
	148: "gatekeeper_user_override",
	149: "tcc_modify",
}

func esfOperationNameFallback(raw int) string {
	if name, ok := esfOperationByType[raw]; ok {
		return name
	}
	return "unknown"
}
