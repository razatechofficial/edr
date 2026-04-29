//go:build !linux

package collector

import (
	"context"
	"os"
	"time"
)

// collectLinux is a no-op on non-Linux platforms; Collect routes to ps/ETW
// instead. This stub exists so the shared method can be referenced
// unconditionally from collector.go.
func (c *ProcessCollector) collectLinux(ctx context.Context) ([]Telemetry, error) {
	return c.collectFromPS(ctx, time.Now().UTC(), os.Getenv("USER"))
}
