package collector

import (
	"strings"
)

// parseSSLine parses a data row from `ss -tuan` / `ss -tan` style output.
func parseSSLine(line string) (connEntry, bool) {
	line = strings.TrimSpace(line)
	if line == "" || strings.HasPrefix(line, "Netid") || strings.HasPrefix(line, "State") {
		return connEntry{}, false
	}
	fields := strings.Fields(line)
	if len(fields) < 2 {
		return connEntry{}, false
	}
	proto := strings.ToLower(fields[0])
	if proto != "tcp" && proto != "udp" {
		return connEntry{}, false
	}
	var candidates []string
	for _, f := range fields[1:] {
		if strings.HasPrefix(f, "users:") {
			break
		}
		if strings.HasPrefix(f, "timer:") || strings.HasPrefix(f, "cgroup:") {
			continue
		}
		if !strings.Contains(f, ":") {
			continue
		}
		host, port := splitHostPortSocket(f)
		if host != "" && port > 0 {
			candidates = append(candidates, f)
		}
	}
	if len(candidates) < 2 {
		return connEntry{}, false
	}
	local, foreign := candidates[0], candidates[1]
	srcIP, srcPort := splitHostPortSocket(local)
	dstIP, dstPort := splitHostPortSocket(foreign)
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
