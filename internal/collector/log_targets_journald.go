//go:build !linux

package collector

import (
	"context"
	"fmt"
)

func (l *LogTargetsCollector) collectJournaldSnapshot(ctx context.Context, st *logTargetRuntime) ([]Telemetry, uint64, error) {
	_ = l
	_ = ctx
	_ = st
	return nil, 0, fmt.Errorf("journald target requires linux")
}
