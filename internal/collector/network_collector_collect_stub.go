//go:build !windows

package collector

import "context"

func (nc *NetworkCollector) collectWindowsMIB(ctx context.Context) ([]Telemetry, error) {
	_ = nc
	_ = ctx
	return nil, nil
}
