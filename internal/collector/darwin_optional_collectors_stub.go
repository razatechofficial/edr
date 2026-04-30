//go:build !darwin

package collector

import "github.com/razatechofficial/edr/internal/config"

func extendDarwinMonitoringCollectors(cols []Collector, _ config.Config, _ string, _ *LineageTracker) []Collector {
	return cols
}
