//go:build windows

package collector

import (
	"fmt"
	"strconv"
	"strings"
)

// AnalyzeWindowsPostureProbes converts Windows posture probe output into findings.
func AnalyzeWindowsPostureProbes(probes map[string]any) []PostureFinding {
	if len(probes) == 0 {
		return nil
	}
	var out []PostureFinding
	for name, raw := range probes {
		m, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		if f, ok := findingForWindowsPostureProbe(name, m); ok {
			out = append(out, f)
		}
	}
	return out
}

func findingForWindowsPostureProbe(name string, m map[string]any) (PostureFinding, bool) {
	switch strings.ToLower(name) {
	case "posture_win_amsi":
		if postureIntFromAny(m["count"]) == 0 && m["error"] == nil {
			return PostureFinding{
				ProbeID: name,
				Title:   "No AMSI providers registered",
				Detail:  "AMSI provider count is zero",
			}, true
		}
	case "posture_win_bcd":
		if v, ok := m["secure_boot_hint"].(bool); ok && !v && m["error"] == nil {
			return PostureFinding{
				ProbeID: name,
				Title:   "Secure Boot not indicated in BCD",
				Detail:  "bcdedit output lacks secure boot markers",
			}, true
		}
	case "posture_win_defender_excl":
		line := postureStringFromAny(m["exclusion_path_count_line"])
		if n, err := strconv.Atoi(strings.TrimSpace(line)); err == nil && n > 25 {
			return PostureFinding{
				ProbeID: name,
				Title:   "Excessive Defender exclusions",
				Detail:  fmt.Sprintf("exclusion_path_count=%d", n),
			}, true
		}
	case "posture_win_wmi":
		for _, key := range []string{"event_filters", "event_consumers", "filter_bindings"} {
			if n := postureIntFromAny(m[key]); n > 50 {
				return PostureFinding{
					ProbeID: name,
					Title:   "Unusual WMI persistence surface",
					Detail:  fmt.Sprintf("%s=%d", key, n),
				}, true
			}
		}
	}
	return PostureFinding{}, false
}
