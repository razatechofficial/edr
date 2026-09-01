package hostperm

import (
	"bytes"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

var (
	adhocSensorTCC = regexp.MustCompile(`(?i)edr-agent-[0-9a-f]{8,}`)
	adhocEDRTCC    = regexp.MustCompile(`(?i)\bedr-[0-9a-f]{8,}`)
)

// tccRawGrantsProduct is a schema-independent fallback: sqlite3 on a temp copy
// can miss Sequoia columns, but the client string is still in the DB bytes.
func tccRawGrantsSensor(raw []byte) bool {
	if len(raw) == 0 {
		return false
	}
	low := bytes.ToLower(raw)
	for _, n := range [][]byte{
		[]byte("/library/application support/edr/bin/edr-agent"),
		[]byte("/usr/local/libexec/edr-agent.app"),
		[]byte("/usr/local/bin/edr-agent"),
		[]byte("com.razatech.edr-agent"),
	} {
		if bytes.Contains(low, n) {
			return true
		}
	}
	return adhocSensorTCC.Match(raw)
}

func tccRawGrantsProduct(raw []byte) bool {
	if len(raw) == 0 {
		return false
	}
	low := bytes.ToLower(raw)
	for _, n := range [][]byte{
		[]byte("/library/application support/edr/bin/edr-agent"),
		[]byte("/library/application support/edr/bin/edr"),
		[]byte("/usr/local/libexec/edr-agent"),
		[]byte("com.razatech.edr-agent"),
		[]byte("com.razatech.edr.console"),
		[]byte("edr-agent.app"),
		[]byte("edr agent.app"),
		[]byte("/applications/edr.app"),
		[]byte("\x00edrctl\x00"),
		[]byte("identifier=edrctl"),
	} {
		if bytes.Contains(low, n) {
			return true
		}
	}
	if bytes.Contains(low, []byte("edrctl")) && bytes.Contains(low, []byte("allfiles")) {
		return true
	}
	return adhocSensorTCC.Match(raw) || adhocEDRTCC.Match(raw)
}

func sensorTCCGranted(clients []string) bool {
	return productTCCGranted(clients)
}

func productTCCGranted(clients []string) bool {
	for _, c := range clients {
		if isProductTCCClient(c) {
			return true
		}
	}
	return false
}

// isProductTCCClient is true for any on-host edr binary or app (sensor, console, CLI).
func isProductTCCClient(client string) bool {
	c := strings.TrimSpace(client)
	if c == "" {
		return false
	}
	low := strings.ToLower(filepath.ToSlash(c))
	if strings.Contains(low, "com.razatech.edr") {
		return true
	}
	if strings.Contains(low, "edr agent.app") || strings.Contains(low, "/applications/edr.app") {
		return true
	}
	if strings.Contains(low, "edr-agent.app") {
		return true
	}
	if strings.Contains(low, "/usr/local/libexec/edr") {
		return true
	}
	if strings.Contains(low, "/library/application support/edr/") {
		return true
	}
	base := strings.ToLower(filepath.Base(c))
	switch base {
	case "edr", "edr.exe", "edrctl", "edrctl.exe", "edr-agent", "edr-agent.exe",
		"edr-agent-ui", "edr-agent-ui.exe", "edr.app":
		return true
	}
	if strings.HasPrefix(base, "edr-agent") || strings.HasPrefix(base, "edrctl") {
		return true
	}
	if strings.HasPrefix(base, "edr-") && adhocEDRTCC.MatchString(base) {
		return true
	}
	return strings.Contains(low, "edr-agent") || strings.Contains(low, "/edr.app/")
}

// isSensorTCCClient is kept for tests and sensor-path matching.
func isSensorTCCClient(client string) bool {
	return isProductTCCClient(client)
}

// sensorListedInTCC is true only when TCC granted FDA to the sensor
// binary (or its LaunchDaemon bundle), not the operator console or Setup.
func sensorListedInTCC(clients []string, sensorPath string) bool {
	sensorPath = strings.TrimSpace(sensorPath)
	for _, c := range clients {
		c = strings.TrimSpace(c)
		if c == "" || isConsoleOrSetupTCCClient(c) {
			continue
		}
		if isSensorBinaryTCCClient(c, sensorPath) {
			return true
		}
	}
	return false
}

func isConsoleOrSetupTCCClient(client string) bool {
	low := strings.ToLower(filepath.ToSlash(client))
	switch {
	case strings.Contains(low, "edr-agent-ui"),
		strings.Contains(low, "com.razatech.edr.console"),
		strings.Contains(low, "com.razatech.edr.setup"),
		strings.Contains(low, "edr-agent-setup"),
		strings.Contains(low, "/applications/edr agent.app"):
		return true
	default:
		return false
	}
}

func isSensorBinaryTCCClient(client, sensorPath string) bool {
	low := strings.ToLower(filepath.ToSlash(client))
	if isConsoleOrSetupTCCClient(client) {
		return false
	}
	if sensorPath != "" {
		sp := strings.ToLower(filepath.ToSlash(sensorPath))
		if strings.EqualFold(client, sensorPath) || strings.Contains(low, sp) {
			return true
		}
		if strings.EqualFold(filepath.Base(client), filepath.Base(sensorPath)) {
			return true
		}
	}
	base := strings.ToLower(filepath.Base(client))
	switch base {
	case "edr-agent", "edr-agent.exe":
		return true
	}
	return strings.Contains(low, "com.razatech.edr-agent") ||
		strings.Contains(low, "/usr/local/libexec/edr-agent") ||
		strings.Contains(low, "/library/application support/edr/bin/edr-agent") ||
		strings.Contains(low, "edr-agent.app")
}

func parseTCCClientRows(out string) []string {
	var clients []string
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		client := line
		auth := 2
		if i := strings.LastIndex(line, "|"); i >= 0 {
			client = strings.TrimSpace(line[:i])
			if v, err := strconv.Atoi(strings.TrimSpace(line[i+1:])); err == nil {
				auth = v
			}
		}
		if client == "" || auth == 0 || auth == 1 {
			continue
		}
		clients = append(clients, client)
	}
	return clients
}

func protectedReadLooksGranted(msg string) bool {
	msg = strings.ToLower(msg)
	if strings.Contains(msg, "operation not permitted") || strings.Contains(msg, "permission denied") {
		return false
	}
	if strings.Contains(msg, "reading config") && (strings.Contains(msg, "not permitted") || strings.Contains(msg, "denied")) {
		return false
	}
	return strings.Contains(msg, "parsing config") ||
		strings.Contains(msg, "unmarshal") ||
		strings.Contains(msg, "cannot unmarshal") ||
		strings.Contains(msg, "yaml:")
}
