//go:build !linux && !darwin

package collector

import "github.com/razatechofficial/edr/internal/config"

func chooseNetworkCollector(cfg config.Config, endpointID string, _ *LineageTracker) Collector {
	if nc := NewNetworkCollector(endpointID, cfg); nc != nil {
		return nc
	}
	return NewNetworkStubCollector(endpointID)
}
