//go:build windows

package main

import (
	"os/exec"
	"strconv"
	"strings"
)

func sampleAgentProcess() (cpu, memMB float64, uptime string, ok bool) {
	cmd := exec.Command("tasklist", "/FI", "IMAGENAME eq edr-agent.exe", "/FO", "CSV", "/NH")
	hideConsole(cmd)
	out, err := cmd.Output()
	if err != nil {
		return 0, 0, "", false
	}
	line := strings.TrimSpace(string(out))
	if line == "" || strings.Contains(strings.ToLower(line), "no tasks") {
		return 0, 0, "", false
	}
	// "edr-agent.exe","1234","Session","1","186,432 K"
	parts := strings.Split(line, ",")
	if len(parts) < 5 {
		return 0, 0, "", false
	}
	mem := strings.Trim(parts[len(parts)-1], " \"K")
	mem = strings.ReplaceAll(mem, ",", "")
	kb, _ := strconv.ParseFloat(strings.TrimSpace(mem), 64)
	if kb <= 0 {
		return 0, 0, "", false
	}
	return 0, kb / 1024, "", true
}
