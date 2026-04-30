//go:build linux

package collector

import (
	"os"
	"os/exec"

	"github.com/razatechofficial/edr/internal/config"
)

func pickLinuxAuth(cfg config.Config, endpointID string, tracker *LineageTracker) (Collector, bool) {
	ac := NewAuthCollector(endpointID, cfg.Agent.DataDir)
	if ac.logPath != "" {
		return ac, cfg.Monitoring.JournaldAuth
	}
	wantJournal := cfg.Monitoring.JournaldAuth || (cfg.Monitoring.LinuxAuthAutoJournal && journalAuthEligible())
	if !wantJournal {
		return ac, false
	}
	flags := []string{
		"--unit=ssh.service", "--unit=sshd.service",
		"--unit=sudo.service", "--unit=systemd-logind.service",
		"--priority=info",
	}
	j := NewJournaldSource(endpointID, "", tracker, flags)
	return newJournalAuthPillarCollector(j, cfg.Monitoring.StreamMaxEPS), false
}

func journalAuthEligible() bool {
	if _, err := os.Stat("/run/systemd/journal/socket"); err != nil {
		return false
	}
	_, err := exec.LookPath("journalctl")
	return err == nil
}
