//go:build windows

package collector

import (
	"context"
	"time"
)

// collectNative uses CreateToolhelp32Snapshot to enumerate processes, freeing
// the agent from the prior single-PID stub (which only emitted edr-agent).
// The source is created lazily.
func (c *ProcessCollector) collectNative(ctx context.Context, _ time.Time, _ string) ([]Telemetry, error) {
	c.mu.Lock()
	src, _ := c.linuxImpl.(*WindowsProcSource)
	if src == nil {
		src = NewWindowsProcSource(c.EndpointID, c.Hostname, c.tracker)
		c.linuxImpl = src
	}
	c.mu.Unlock()
	return src.Snapshot(ctx)
}
