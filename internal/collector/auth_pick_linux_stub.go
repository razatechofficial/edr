//go:build !linux

package collector

import "github.com/razatechofficial/edr/internal/config"

func pickLinuxAuth(cfg config.Config, endpointID string, tracker *LineageTracker) (Collector, bool) {
	_ = cfg
	_ = tracker
	return NewAuthStubCollector(endpointID), false
}
