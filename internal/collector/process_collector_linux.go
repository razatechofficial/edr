//go:build linux

package collector

import "context"

// collectLinux uses the lightweight /proc diff source instead of forking ps.
// The ProcSource is created lazily on first call so the collector cost is
// nil until something actually polls.
func (c *ProcessCollector) collectLinux(ctx context.Context) ([]Telemetry, error) {
	c.mu.Lock()
	src, _ := c.linuxImpl.(*ProcSource)
	if src == nil {
		src = NewProcSource(c.EndpointID, c.Hostname, c.tracker)
		c.linuxImpl = src
	}
	c.mu.Unlock()
	return src.Snapshot(ctx)
}
