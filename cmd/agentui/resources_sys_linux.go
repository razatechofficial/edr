//go:build linux

package main

import (
	"bufio"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

var (
	cpuMu         sync.Mutex
	lastIdle      uint64
	lastTotal     uint64
	lastCPUSample time.Time
)

func sampleSystem() (cpuPct float64, memUsed, memTotal uint64) {
	memTotal, memAvail := readMeminfo()
	if memTotal >= memAvail {
		memUsed = memTotal - memAvail
	}
	idle, total := readProcStat()
	cpuMu.Lock()
	defer cpuMu.Unlock()
	if lastTotal > 0 && total > lastTotal {
		didle := idle - lastIdle
		dtotal := total - lastTotal
		if dtotal > 0 {
			busy := 1 - float64(didle)/float64(dtotal)
			if busy < 0 {
				busy = 0
			}
			cpuPct = busy * 100
		}
	} else {
		time.Sleep(120 * time.Millisecond)
		idle2, total2 := readProcStat()
		if total2 > total {
			cpuPct = (1 - float64(idle2-idle)/float64(total2-total)) * 100
		}
	}
	lastIdle, lastTotal = idle, total
	lastCPUSample = time.Now()
	return cpuPct, memUsed, memTotal
}

func readMeminfo() (total, avail uint64) {
	f, err := os.Open("/proc/meminfo")
	if err != nil {
		return 0, 0
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		switch {
		case strings.HasPrefix(line, "MemTotal:"):
			total = parseKB(line) * 1024
		case strings.HasPrefix(line, "MemAvailable:"):
			avail = parseKB(line) * 1024
		}
	}
	return total, avail
}

func parseKB(line string) uint64 {
	fields := strings.Fields(line)
	if len(fields) < 2 {
		return 0
	}
	n, _ := strconv.ParseUint(fields[1], 10, 64)
	return n
}

func readProcStat() (idle, total uint64) {
	b, err := os.ReadFile("/proc/stat")
	if err != nil {
		return 0, 0
	}
	line, _, _ := strings.Cut(string(b), "\n")
	fields := strings.Fields(line)
	if len(fields) < 5 || fields[0] != "cpu" {
		return 0, 0
	}
	var vals []uint64
	for _, f := range fields[1:] {
		n, _ := strconv.ParseUint(f, 10, 64)
		vals = append(vals, n)
		total += n
	}
	if len(vals) > 3 {
		idle = vals[3]
	}
	if len(vals) > 4 {
		idle += vals[4] // iowait
	}
	return idle, total
}
