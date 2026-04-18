//go:build !windows

package collector

import "context"

// NewRegistryCollector returns nil on non-Windows platforms.
func NewRegistryCollector(_ string) *RegistryCollector {
	return nil
}

// RegistryCollector is a no-op placeholder on non-Windows platforms.
type RegistryCollector struct{}

func (rc *RegistryCollector) Name() string                                  { return "registry" }
func (rc *RegistryCollector) Collect(_ context.Context) ([]Telemetry, error) { return nil, nil }
