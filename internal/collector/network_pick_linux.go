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
	_ = cfg
	// Linux now uses a single canonical network implementation:
	// PID-attributed socket snapshots from SocketSource.
	// Legacy /proc_net polling collector is no longer selected on Linux.
	return newLinuxSocketNetworkCollector(endpointID, tracker)
}
