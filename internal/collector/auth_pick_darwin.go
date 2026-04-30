//go:build darwin

package collector

import (
	"os"
	"os/exec"

	"github.com/razatechofficial/edr/internal/config"
)

func pickDarwinAuth(cfg config.Config, endpointID string, tracker *LineageTracker) Collector {
	ac := NewAuthCollector(endpointID, cfg.Agent.DataDir)
	if authLogPathReadable(ac.logPath) {
		return ac
	}
	if cfg.Monitoring.DarwinAuthUnifiedLog && logBinaryPresent() {
		return newDarwinUnifiedAuthPillar(NewDarwinAuthUnifiedSource(endpointID, tracker), cfg.Monitoring.StreamMaxEPS)
	}
	return ac
}

func authLogPathReadable(p string) bool {
	if p == "" {
		return false
	}
	f, err := os.Open(p)
	if err != nil {
		return false
	}
	_ = f.Close()
	return true
}

func logBinaryPresent() bool {
	_, err := exec.LookPath("log")
	return err == nil
}
