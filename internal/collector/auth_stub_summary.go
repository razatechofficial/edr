package collector

import (
	"os"
	"runtime"
	"strings"
)

func authStubProbeSummary() string {
	switch runtime.GOOS {
	case "windows":
		return "windows stub: Security.evtx path requires AuthCollector (non-stub)"
	default:
		paths := []string{"/var/log/auth.log", "/var/log/secure", "/var/log/authlog"}
		var parts []string
		for _, p := range paths {
			if _, err := os.Stat(p); err == nil {
				parts = append(parts, p+"=present")
			} else {
				parts = append(parts, p+"=missing")
			}
		}
		return "probed_paths: " + strings.Join(parts, ", ")
	}
}
