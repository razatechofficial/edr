package collector

import (
	"strings"
)

// parseLsofInetLine parses `lsof -i -n -P` lines that contain " TCP " or " UDP "
// with a `local->remote` socket description.
func parseLsofInetLine(line string) (connEntry, bool) {
	var proto string
	switch {
	case strings.Contains(line, " TCP "):
		proto = "tcp"
	case strings.Contains(line, " UDP "):
		proto = "udp"
	default:
		return connEntry{}, false
	}
	needle := " " + strings.ToUpper(proto) + " "
	idx := strings.Index(line, needle)
	if idx < 0 {
		return connEntry{}, false
	}
	rest := strings.TrimSpace(line[idx+len(needle):])
	arrow := strings.Index(rest, "->")
	if arrow < 0 {
		return connEntry{}, false
	}
	left := strings.TrimSpace(rest[:arrow])
	right := strings.TrimSpace(rest[arrow+2:])
	if sp := strings.IndexByte(right, ' '); sp >= 0 {
		right = right[:sp]
	}
	srcIP, srcPort := splitHostPortSocket(left)
	dstIP, dstPort := splitHostPortSocket(right)
	if dstIP == "" || dstPort == 0 {
		return connEntry{}, false
	}
	return connEntry{
		proto:   proto,
		srcIP:   srcIP,
		srcPort: srcPort,
		dstIP:   dstIP,
		dstPort: dstPort,
	}, true
}
