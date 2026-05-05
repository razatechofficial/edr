//go:build !linux && !darwin && !windows

package collector

import (
	"os"

	"github.com/razatechofficial/edr/internal/config"
)

func pickRareOrPrimaryAuth(cfg config.Config, endpointID string, tracker *LineageTracker) Collector {
	return pickRareOrPrimaryAuthFromPaths(cfg, endpointID, tracker, []string{
		"/var/log/auth.log", "/var/log/secure", "/var/log/authlog",
	})
}

func pickRareOrPrimaryAuthFromPaths(cfg config.Config, endpointID string, _ *LineageTracker, candidates []string) Collector {
	for _, p := range candidates {
		if authPathReadable(p) {
			return NewRareAuthCollector(endpointID, p)
		}
	}
	if ac := NewAuthCollector(endpointID, cfg.Agent.DataDir); ac != nil && ac.logPath != "" {
		return ac
	}
	return NewRareAuthCollector(endpointID, "/var/log/messages")
}

func authPathReadable(p string) bool {
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
