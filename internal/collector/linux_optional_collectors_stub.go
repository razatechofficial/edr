//go:build !linux

package collector

import "github.com/razatechofficial/edr/internal/config"

func extendLinuxMonitoringCollectors(cols []Collector, _ config.Config, _ string, _ *LineageTracker, _ bool) []Collector {
	return cols
}
