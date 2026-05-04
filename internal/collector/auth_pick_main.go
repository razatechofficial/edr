//go:build linux || darwin || windows

package collector

import "github.com/razatechofficial/edr/internal/config"

func pickRareOrPrimaryAuth(cfg config.Config, endpointID string, _ *LineageTracker) Collector {
	if ac := NewAuthCollector(endpointID, cfg.Agent.DataDir); ac != nil && ac.logPath != "" {
		return ac
	}
	return NewAuthStubCollector(endpointID)
}
