package collector

import (
	"strconv"
	"strings"
)

// parseNetstatLine parses common `netstat -an` rows (BSD and Linux table layouts).
func parseNetstatLine(line string) (connEntry, bool) {
	fields := strings.Fields(line)
	if len(fields) < 5 {
		return connEntry{}, false
	}
	proto := strings.ToLower(fields[0])
	pkind := ""
	switch {
	case strings.HasPrefix(proto, "tcp"):
		pkind = "tcp"
	case strings.HasPrefix(proto, "udp"):
		pkind = "udp"
	default:
		return connEntry{}, false
	}
	local := fields[3]
	remote := fields[4]
	if remote == "*.*" || remote == "*:*" || remote == ":::*" || strings.TrimSpace(remote) == "" {
		return connEntry{}, false
	}
	srcIP, srcPort := splitHostPortSocket(local)
	dstIP, dstPort := splitHostPortSocket(remote)
	if dstIP == "" || dstPort == 0 {
		return connEntry{}, false
	}
	if strings.Contains(dstIP, "*") {
		return connEntry{}, false
	}
	return connEntry{
		proto:   pkind,
		srcIP:   srcIP,
		srcPort: srcPort,
		dstIP:   dstIP,
		dstPort: dstPort,
	}, true
}

func splitHostPortSocket(s string) (string, int) {
	s = strings.TrimSpace(s)
	if s == "" {
		return "", 0
	}
	if strings.HasPrefix(s, "[") {
		closeIdx := strings.Index(s, "]")
		if closeIdx < 0 {
			return "", 0
		}
		ip := s[1:closeIdx]
		rest := strings.TrimSpace(s[closeIdx+1:])
		if !strings.HasPrefix(rest, ".") && !strings.HasPrefix(rest, ":") {
			return "", 0
		}
		rest = strings.TrimPrefix(rest, ".")
		rest = strings.TrimPrefix(rest, ":")
		port, err := strconv.Atoi(rest)
		if err != nil {
			return "", 0
		}
		return ip, port
	}
	if strings.Contains(s, ":") {
		i := strings.LastIndex(s, ":")
		if i <= 0 || i == len(s)-1 {
			return "", 0
		}
		host := s[:i]
		port, err := strconv.Atoi(s[i+1:])
		if err != nil || strings.Contains(host, "*") {
			return "", 0
		}
		return host, port
	}
	i := strings.LastIndex(s, ".")
	if i <= 0 || i == len(s)-1 {
		return "", 0
	}
	host := s[:i]
	port, err := strconv.Atoi(s[i+1:])
	if err != nil || strings.Contains(host, "*") {
		return "", 0
	}
	return host, port
}
