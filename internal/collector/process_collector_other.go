//go:build !linux && !darwin && !windows

package collector

import (
	"context"
	"time"
)

// collectNative is the non–tier-1 Unix fallback: bounded `ps` snapshot.
// Windows and macOS use their own build-tagged collectNative implementations.
func (c *ProcessCollector) collectNative(ctx context.Context, now time.Time, user string) ([]Telemetry, error) {
	return c.collectFromPS(ctx, now, user)
}
