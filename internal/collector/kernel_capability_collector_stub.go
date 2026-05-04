//go:build !(linux || windows || (darwin && cgo && !nosec))

package collector

import "github.com/razatechofficial/edr/internal/config"

// newKernelCapabilityProbeCollectorWhenNil is only used on Linux, Windows, and
// production macOS (darwin+cgo+!nosec). Other builds attach kernel via
// kernel_collector_other.go which always returns a non-nil capability probe.
func newKernelCapabilityProbeCollectorWhenNil(string, config.Config, *UsernameCache) Collector {
	return nil
}
