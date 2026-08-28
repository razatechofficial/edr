//go:build darwin

package main

import (
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"

	"github.com/razatechofficial/edr/internal/platform"
)

func sampleAgentProcess() (cpu, memMB float64, uptime string, ok bool) {
	pid := agentPID()
	if pid <= 0 {
		return 0, 0, "", false
	}
	out, err := exec.Command("ps", "-o", "%cpu=,rss=,etime=", "-p", strconv.Itoa(pid)).Output()
	if err != nil {
		return 0, 0, "", false
	}
	fields := strings.Fields(string(out))
	if len(fields) < 2 {
		return 0, 0, "", false
	}
	cpu, _ = strconv.ParseFloat(fields[0], 64)
	rssKB, _ := strconv.ParseFloat(fields[1], 64)
	memMB = rssKB / 1024
	if len(fields) >= 3 {
		uptime = parseEtime(fields[2])
	}
	return cpu, memMB, uptime, true
}

func agentPID() int {
	if b, err := os.ReadFile(platform.PIDFile()); err == nil {
		pid, _ := strconv.Atoi(strings.TrimSpace(string(b)))
		if pid > 1 && processExists(pid) {
			return pid
		}
	}
	out, err := exec.Command("pgrep", "-x", "edr-agent").Output()
	if err != nil {
		return 0
	}
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		pid, err := strconv.Atoi(strings.TrimSpace(line))
		if err == nil && pid > 1 {
			return pid
		}
	}
	return 0
}

func processExists(pid int) bool {
	return syscall.Kill(pid, 0) == nil
}
