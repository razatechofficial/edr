//go:build linux || darwin || windows

package collector

import "context"

func gatherOtherPlatformConnections(_ context.Context, _ *NetworkCollector) ([]Telemetry, error) {
	return nil, nil
}
