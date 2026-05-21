package ocsf

import "strings"

// knownESFActions are process_name / esf_op values used by macOS Sigma rules as event.action.
var knownESFActions = map[string]struct{}{
	"exec": {}, "fork": {}, "exit": {}, "open": {}, "create": {}, "rename": {},
	"unlink": {}, "write": {}, "truncate": {}, "signal": {}, "kextload": {},
	"image_load": {}, "mprotect": {}, "mount": {}, "get_task": {}, "xpc_connect": {},
	"setuid": {}, "setgid": {}, "cs_invalidated": {}, "gatekeeper_user_override": {},
	"tcc_modify": {}, "screensharing_attach": {}, "screensharing_detach": {},
	"xp_malware_detected": {}, "xp_malware_remediated": {},
}

// enrichDarwinSigmaFields adds macOS ESF / Unified Logging aliases expected by imported Sigma rules.
func enrichDarwinSigmaFields(out map[string]interface{}) {
	if len(out) == 0 {
		return
	}
	osName := strings.ToLower(stringField(out, "os", "OS"))
	hasESF := intField(out, "esf_type") != 0 || stringField(out, "esf_op") != ""
	hasUL := stringField(out, "subsystem") != ""
	if osName != "darwin" && !hasESF && !hasUL {
		return
	}

	if v := intField(out, "esf_type"); v != 0 {
		setIfAbsent(out, "esf.event_type", v)
	}

	action := firstNonEmptyString(
		stringField(out, "esf_op"),
		stringField(out, "operation"),
	)
	if action == "" {
		pn := stringField(out, "process_name")
		if _, ok := knownESFActions[pn]; ok {
			action = pn
		}
	}
	if action != "" {
		setIfAbsent(out, "event.action", action)
	}

	if v := stringField(out, "target_image"); v != "" {
		setIfAbsent(out, "TargetImage", v)
	} else if action == "signal" {
		if p := stringField(out, "process_path", "path"); p != "" {
			setIfAbsent(out, "TargetImage", p)
		}
	}

	if v := intField(out, "signal_number", "signal"); v != 0 {
		setIfAbsent(out, "SignalNumber", v)
	}

	if msg := stringField(out, "message"); msg != "" {
		setIfAbsent(out, "CommandLine", msg)
	}

	if sub := stringField(out, "subsystem"); sub != "" {
		setIfAbsent(out, "logsource.service", "unifiedlog")
	}
	if cat := stringField(out, "category"); cat != "" {
		setIfAbsent(out, "category", cat)
	}
	if v := stringField(out, "xpc_service"); v != "" {
		setIfAbsent(out, "xpc_service", v)
	}
}

func firstNonEmptyString(vals ...string) string {
	for _, s := range vals {
		if strings.TrimSpace(s) != "" {
			return s
		}
	}
	return ""
}
