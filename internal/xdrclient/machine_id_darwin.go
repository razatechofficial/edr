//go:build darwin

package xdrclient

import "strings"

// platformSystemUUID returns Apple IOPlatformUUID (OCSF hw_info.uuid on macOS).
func platformSystemUUID() string {
	out := runTrim("/usr/sbin/ioreg", "-rd1", "-c", "IOPlatformExpertDevice")
	for _, line := range strings.Split(out, "\n") {
		if !strings.Contains(line, "IOPlatformUUID") {
			continue
		}
		parts := strings.Split(line, "=")
		if len(parts) < 2 {
			continue
		}
		s := strings.TrimSpace(parts[len(parts)-1])
		s = strings.Trim(s, `"`)
		if s != "" {
			return s
		}
	}
	return ""
}
