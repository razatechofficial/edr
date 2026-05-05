//go:build !linux && !darwin && !windows

package collector

import (
	"os"
	"os/exec"
	"strings"
)

func probeRareDNSSource(extra []string) (path string, probes []string, winner string) {
	candidates := []string{
		"/var/log/messages",
		"/var/log/syslog",
		"/var/log/system.log",
		"/var/log/daemon.log",
	}
	candidates = append(candidates, extra...)
	probes = append(probes, "log_path_scan")
	for _, p := range candidates {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		if _, err := os.Stat(p); err == nil {
			return p, probes, "syslog_tail"
		}
	}
	probes = append(probes, "journalctl_poll")
	if _, err := exec.LookPath("journalctl"); err == nil {
		return "", probes, "command_poll"
	}
	return "", probes, "unconfigured"
}
