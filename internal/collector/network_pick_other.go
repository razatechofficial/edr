//go:build !linux && !darwin

package collector

import "github.com/razatechofficial/edr/internal/config"

func chooseNetworkCollector(_ config.Config, endpointID string, _ *LineageTracker) Collector {
	if nc := NewNetworkCollector(endpointID); nc != nil {
		return nc
	}
	return NewNetworkStubCollector(endpointID)
}
