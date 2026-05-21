//go:build darwin

package kernel

// esfOperationByType maps raw ESF event type integers to Sigma event.action
// strings when the C esfOperationName switch returns unknown (newer SDK types).
var esfOperationByType = map[int]string{
	24:  "setuid",
	25:  "setgid",
	62:  "cs_invalidated",
	65:  "xpc_connect",
	112: "xp_malware_detected",
	113: "xp_malware_remediated",
	135: "screensharing_attach",
	136: "screensharing_detach",
	146: "gatekeeper_user_override",
	147: "tcc_modify",
}

func esfOperationNameFallback(raw int) string {
	if name, ok := esfOperationByType[raw]; ok {
		return name
	}
	return "unknown"
}
