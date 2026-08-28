//go:build !darwin && !windows

package main

import (
	"os"
	"os/exec"
	"strconv"
	"strings"
)

func sampleAgentProcess() (cpu, memMB float64, uptime string, ok bool) {
	out, err := exec.Command("pgrep", "-x", "edr-agent").Output()
	if err != nil {
		return 0, 0, "", false
	}
	pid := 0
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		n, err := strconv.Atoi(strings.TrimSpace(line))
		if err == nil && n > 1 {
			pid = n
			break
		}
	}
	if pid <= 0 {
		return 0, 0, "", false
	}
	raw, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/status")
	if err != nil {
		return 0, 0, "", false
	}
	for _, line := range strings.Split(string(raw), "\n") {
		if strings.HasPrefix(line, "VmRSS:") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				kb, _ := strconv.ParseFloat(fields[1], 64)
				memMB = kb / 1024
				ok = true
			}
		}
	}
	return cpu, memMB, "", ok
}
