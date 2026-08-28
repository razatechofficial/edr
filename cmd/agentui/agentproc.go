package main

import (
	"bufio"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/razatechofficial/edr/internal/platform"
)

func parseEtime(s string) string {
	s = strings.TrimSpace(s)
	if s == "" || s == "-" {
		return ""
	}
	days := 0
	rest := s
	if i := strings.IndexByte(s, '-'); i >= 0 {
		days, _ = strconv.Atoi(s[:i])
		rest = s[i+1:]
	}
	parts := strings.Split(rest, ":")
	var h, m int
	switch len(parts) {
	case 3:
		h, _ = strconv.Atoi(parts[0])
		m, _ = strconv.Atoi(parts[1])
	case 2:
		m, _ = strconv.Atoi(parts[0])
	default:
		return s
	}
	h += days * 24
	switch {
	case h >= 24:
		return strconv.Itoa(h/24) + "d " + strconv.Itoa(h%24) + "h"
	case h > 0:
		return strconv.Itoa(h) + "h " + strconv.Itoa(m) + "m"
	default:
		return strconv.Itoa(m) + "m"
	}
}

func countJSONL(path string) uint64 {
	f, err := os.Open(path)
	if err != nil {
		return 0
	}
	defer f.Close()
	var n uint64
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 4<<20)
	for sc.Scan() {
		if strings.TrimSpace(sc.Text()) != "" {
			n++
		}
	}
	return n
}

func countTreeFiles(root string) uint64 {
	var n uint64
	_ = filepath.Walk(root, func(_ string, info os.FileInfo, err error) error {
		if err != nil || info == nil || info.IsDir() {
			return nil
		}
		n++
		return nil
	})
	return n
}

func localRulesCount() int {
	return int(countTreeFiles(platform.RulesDir()))
}

func localAlertCount() uint64 {
	if p := platform.ResolveAlertFile(); p != "" {
		if n := countJSONL(p); n > 0 {
			return n
		}
	}
	for _, p := range platform.AlertFileCandidates() {
		if n := countJSONL(p); n > 0 {
			return n
		}
	}
	return 0
}

func localBlockCount() uint64 {
	return countTreeFiles(platform.QuarantineDir())
}

func enrichStatus(st *operatorStatus) {
	cpu, mem, up, ok := sampleAgentProcess()
	if ok {
		if st.CPUPercent == 0 {
			st.CPUPercent = cpu
		}
		if st.MemoryMB == 0 {
			st.MemoryMB = mem
		}
		if strings.TrimSpace(st.Uptime) == "" {
			st.Uptime = up
		}
	}
	if st.RulesCount == 0 {
		st.RulesCount = localRulesCount()
	}
	if st.Detections == 0 {
		st.Detections = localAlertCount()
	}
	if st.Blocks == 0 {
		st.Blocks = localBlockCount()
	}
}

func processStartUptime(start time.Time) string {
	if start.IsZero() {
		return ""
	}
	d := time.Since(start)
	h := int(d.Hours())
	m := int(d.Minutes()) % 60
	if h >= 24 {
		return strconv.Itoa(h/24) + "d " + strconv.Itoa(h%24) + "h"
	}
	if h > 0 {
		return strconv.Itoa(h) + "h " + strconv.Itoa(m) + "m"
	}
	return strconv.Itoa(m) + "m"
}
