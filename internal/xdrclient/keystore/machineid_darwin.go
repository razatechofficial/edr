//go:build darwin

package keystore

import (
	"os/exec"
	"strings"
)

func darwinPlatformUUID() string {
	out, err := exec.Command("ioreg", "-rd1", "-c", "IOPlatformExpertDevice").Output()
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if !strings.Contains(line, "IOPlatformUUID") {
			continue
		}
		// "IOPlatformUUID" = "XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX"
		parts := strings.Split(line, "=")
		if len(parts) < 2 {
			continue
		}
		id := strings.TrimSpace(parts[1])
		id = strings.Trim(id, `"`)
		if id != "" {
			return id
		}
	}
	return ""
}
