//go:build !linux && !darwin && !windows

package collector

import "github.com/razatechofficial/edr/internal/config"

// NewPostureCollector is enabled only on Linux, Darwin, and Windows.
func NewPostureCollector(cfg config.Config) Collector {
	_ = cfg
	return nil
}
