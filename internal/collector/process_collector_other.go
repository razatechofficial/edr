//go:build !linux && !darwin && !windows

package collector

import (
	"context"
	"time"
)

// collectNative is the non-Linux/non-Darwin fallback. We still honour the
// signature so collector.go stays platform-agnostic, but on Windows the
// ETW-driven collector handles process telemetry; this method is unused.
func (c *ProcessCollector) collectNative(ctx context.Context, now time.Time, user string) ([]Telemetry, error) {
	return c.collectFromPS(ctx, now, user)
}
