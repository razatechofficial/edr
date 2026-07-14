//go:build darwin

package xdrclient

import "strings"

func readHardwareSerial() string {
	// IOPlatformSerialNumber — stable hardware serial (802.1AR-style device serial).
	out := runTrim("/usr/sbin/ioreg", "-rd1", "-c", "IOPlatformExpertDevice")
	for _, line := range strings.Split(out, "\n") {
		if !strings.Contains(line, "IOPlatformSerialNumber") {
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

func readProductModel() string {
	if m := runTrim("/usr/sbin/sysctl", "-n", "hw.model"); m != "" {
		return m
	}
	return ""
}

func readManufacturer() string {
	// Apple hardware; keep explicit for DevID Organization.
	return "Apple"
}
