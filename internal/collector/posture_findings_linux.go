//go:build linux

package collector

import (
	"fmt"
	"strings"
)

// AnalyzePostureProbes converts posture probe JSON into alert-worthy findings.
func AnalyzePostureProbes(probes map[string]any) []PostureFinding {
	if len(probes) == 0 {
		return nil
	}
	var out []PostureFinding
	for name, raw := range probes {
		m, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		if f, ok := findingForPostureProbe(name, m); ok {
			out = append(out, f)
		}
	}
	return out
}

func findingForPostureProbe(name string, m map[string]any) (PostureFinding, bool) {
	switch strings.ToLower(name) {
	case "rootkit_iocs":
		if n := postureIntFromAny(m["ioc_hits"]); n > 0 {
			return PostureFinding{
				ProbeID: name,
				Title:   "Rootkit IOC path present",
				Detail:  fmt.Sprintf("ioc_hits=%d paths=%v", n, m["paths"]),
			}, true
		}
	case "dev_anomaly":
		if n := postureIntFromAny(m["anomaly_count"]); n > 0 {
			return PostureFinding{
				ProbeID: name,
				Title:   "Unexpected file in /dev",
				Detail:  fmt.Sprintf("anomaly_count=%d sample=%v", n, m["sample"]),
			}, true
		}
	case "posture_dev_walker":
		if n := postureIntFromAny(m["unexpected_regular_files"]); n > 0 {
			return PostureFinding{
				ProbeID: name,
				Title:   "Regular files under /dev",
				Detail:  fmt.Sprintf("unexpected_regular_files=%d sample=%v", n, m["sample"]),
			}, true
		}
	case "ld_so_preload_hash":
		if postureBoolFromAny(m["changed"]) {
			return PostureFinding{
				ProbeID: name,
				Title:   "/etc/ld.so.preload changed",
				Detail:  fmt.Sprintf("sha256=%v", m["sha256"]),
			}, true
		}
	case "posture_hidden_port":
		if n := postureIntFromAny(m["row_delta_abs"]); n >= 3 {
			return PostureFinding{
				ProbeID: name,
				Title:   "Possible hidden listening port",
				Detail:  fmt.Sprintf("proc_tcp=%v ss_tln=%v delta=%d", m["proc_tcp_listen_rows"], m["ss_tln_rows"], n),
			}, true
		}
	case "posture_hidden_pid":
		if n := postureIntFromAny(m["kill_zero_failures"]); n > 0 {
			return PostureFinding{
				ProbeID: name,
				Title:   "Proc entry without live process",
				Detail:  fmt.Sprintf("kill_zero_failures=%d checked=%v", n, m["proc_entries_checked"]),
			}, true
		}
	}
	return PostureFinding{}, false
}
