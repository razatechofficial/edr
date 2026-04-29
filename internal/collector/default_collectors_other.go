//go:build !windows

package collector

import "github.com/razatechofficial/edr/internal/config"

func extendWindowsEvtCollectors(cols []Collector, _ config.Config, _ string) []Collector {
	return cols
}
