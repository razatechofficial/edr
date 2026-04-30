//go:build darwin

package collector

import (
	"context"

	"github.com/razatechofficial/edr/internal/config"
)

type darwinAttributedNetworkCollector struct {
	s *DarwinNetworkSource
}

func newDarwinAttributedNetworkCollector(endpointID string, tracker *LineageTracker) *darwinAttributedNetworkCollector {
	return &darwinAttributedNetworkCollector{s: NewDarwinNetworkSource(endpointID, "", tracker)}
}

func (d *darwinAttributedNetworkCollector) Name() string { return "network" }

func (d *darwinAttributedNetworkCollector) Collect(ctx context.Context) ([]Telemetry, error) {
	return d.s.Snapshot(ctx)
}

func (d *darwinAttributedNetworkCollector) ExportMonitoringHealth() map[string]any {
	return d.s.ExportMonitoringHealth()
}

func chooseNetworkCollector(cfg config.Config, endpointID string, tracker *LineageTracker) Collector {
	if cfg.Monitoring.DarwinAttribNetwork {
		return newDarwinAttributedNetworkCollector(endpointID, tracker)
	}
	if nc := NewNetworkCollector(endpointID); nc != nil {
		return nc
	}
	return NewNetworkStubCollector(endpointID)
}
