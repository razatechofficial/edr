//go:build !windows

package collector

import (
	"context"
	"fmt"
)

func (l *LogTargetsCollector) initTargetPlatform(st *logTargetRuntime) {
	_ = l
	_ = st
}

func (l *LogTargetsCollector) collectWindowsEventChannel(ctx context.Context, st *logTargetRuntime) ([]Telemetry, error) {
	_ = ctx
	_ = st
	return nil, fmt.Errorf("eventchannel target requires windows")
}
