//go:build !linux

package collector

import (
	"context"
	"fmt"
)

func (l *LogTargetsCollector) collectJournaldSnapshot(ctx context.Context, st *logTargetRuntime) (uint64, error) {
	_ = l
	_ = ctx
	_ = st
	return 0, fmt.Errorf("journald target requires linux")
}
