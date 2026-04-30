//go:build !darwin

package collector

import "github.com/razatechofficial/edr/internal/config"

func pickDarwinAuth(cfg config.Config, endpointID string, tracker *LineageTracker) Collector {
	_ = cfg
	_ = tracker
	return NewAuthStubCollector(endpointID)
}
