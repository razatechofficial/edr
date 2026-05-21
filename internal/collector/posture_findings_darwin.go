//go:build darwin

package collector

import (
	"fmt"
	"strings"
)

// AnalyzeDarwinPostureProbes converts macOS posture probe output into findings.
func AnalyzeDarwinPostureProbes(probes map[string]any) []PostureFinding {
	if len(probes) == 0 {
		return nil
	}
	var out []PostureFinding
	for name, raw := range probes {
		m, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		if f, ok := findingForDarwinPostureProbe(name, m); ok {
			out = append(out, f)
		}
	}
	return out
}

func findingForDarwinPostureProbe(name string, m map[string]any) (PostureFinding, bool) {
	switch strings.ToLower(name) {
	case "posture_darwin_gatekeeper":
		st := strings.ToLower(postureStringFromAny(m["spctl_status"]))
		if strings.Contains(st, "disabled") {
			return PostureFinding{
				ProbeID: name,
				Title:   "Gatekeeper disabled",
				Detail:  postureStringFromAny(m["spctl_status"]),
			}, true
		}
	case "posture_darwin_codesign":
		for k, v := range m {
			sub, ok := v.(map[string]any)
			if !ok {
				continue
			}
			if _, err := sub["error"]; err {
				return PostureFinding{
					ProbeID: name,
					Title:   "Code signature verification failed",
					Detail:  fmt.Sprintf("binary=%s error=%v", k, sub["error"]),
				}, true
			}
		}
	}
	return PostureFinding{}, false
}
