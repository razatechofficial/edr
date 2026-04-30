package collector

import (
	"strconv"
	"strings"
)

func atoiTrim(s string) int {
	s = strings.TrimSpace(s)
	n, _ := strconv.Atoi(s)
	return n
}

func countNonEmptyLines(s string) int {
	n := 0
	for _, line := range strings.Split(s, "\n") {
		if strings.TrimSpace(line) != "" {
			n++
		}
	}
	return n
}

// parseSsListenerStats interprets stdout from `ss -lntu` / `ss -lntup` (iproute2).
// Returns estimated listener-oriented data rows (excluding typical header line)
// and rows that appear to carry process/socket owner hints (pid= or users:()).
func parseSsListenerStats(text string) (dataRowsEst int, pidHintRows int) {
	lines := strings.Split(text, "\n")
	headerSkipped := false
	for _, raw := range lines {
		line := strings.TrimSpace(raw)
		if line == "" {
			continue
		}
		ls := strings.ToLower(line)
		if strings.Contains(ls, "state") && strings.Contains(ls, "recv-q") {
			headerSkipped = true
			continue
		}
		if !headerSkipped && (strings.HasPrefix(ls, "netid") || strings.HasPrefix(ls, "state")) {
			headerSkipped = true
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		var state string
		switch {
		case strings.ToUpper(fields[0]) == "LISTEN" || strings.ToUpper(fields[0]) == "UNCONN":
			state = strings.ToUpper(fields[0])
		default:
			state = strings.ToUpper(fields[1])
		}
		if state != "LISTEN" && state != "UNCONN" {
			continue
		}
		dataRowsEst++
		if strings.Contains(line, "pid=") || strings.Contains(line, "users:(") {
			pidHintRows++
		}
	}
	return dataRowsEst, pidHintRows
}
