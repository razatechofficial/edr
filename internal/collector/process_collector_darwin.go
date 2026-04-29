//go:build darwin

package collector

import (
	"context"
	"time"
)

// collectNative uses the sysctl-based DarwinProcSource so we no longer fork
// `ps` once per Collect cycle. The source is lazy-initialised so that
// non-process call paths pay nothing.
func (c *ProcessCollector) collectNative(ctx context.Context, _ time.Time, _ string) ([]Telemetry, error) {
	c.mu.Lock()
	src, _ := c.linuxImpl.(*DarwinProcSource)
	if src == nil {
		src = NewDarwinProcSource(c.EndpointID, c.Hostname, c.tracker)
		c.linuxImpl = src
	}
	c.mu.Unlock()
	return src.Snapshot(ctx)
}
