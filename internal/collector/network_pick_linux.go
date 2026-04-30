//go:build linux

package collector

import (
	"context"

	"github.com/razatechofficial/edr/internal/config"
)

type linuxSocketNetworkCollector struct {
	s *SocketSource
}

func newLinuxSocketNetworkCollector(endpointID string, tracker *LineageTracker) *linuxSocketNetworkCollector {
	return &linuxSocketNetworkCollector{s: NewSocketSource(endpointID, "", tracker)}
}

func (c *linuxSocketNetworkCollector) Name() string { return "network" }

func (c *linuxSocketNetworkCollector) Collect(ctx context.Context) ([]Telemetry, error) {
	return c.s.Snapshot(ctx)
}

func (c *linuxSocketNetworkCollector) ExportMonitoringHealth() map[string]any {
	return c.s.ExportMonitoringHealth()
}

func chooseNetworkCollector(cfg config.Config, endpointID string, tracker *LineageTracker) Collector {
	if cfg.Monitoring.LinuxPIDNetwork {
		return newLinuxSocketNetworkCollector(endpointID, tracker)
	}
	if nc := NewNetworkCollector(endpointID, cfg); nc != nil {
		return nc
	}
	return NewNetworkStubCollector(endpointID)
}
