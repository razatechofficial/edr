package detection

import (
	"strings"
	"sync/atomic"
)

var runtimeProfile atomic.Value

func setRuntimeProfile(profile string) {
	p := strings.ToLower(strings.TrimSpace(profile))
	if p == "" {
		p = "balanced"
	}
	runtimeProfile.Store(p)
}

func currentRuntimeProfile() string {
	if v := runtimeProfile.Load(); v != nil {
		if s, ok := v.(string); ok && s != "" {
			return s
		}
	}
	return "balanced"
}

func isLowResourceProfile() bool { return currentRuntimeProfile() == "low_resource" }
func isStrictProfile() bool      { return currentRuntimeProfile() == "strict" }
