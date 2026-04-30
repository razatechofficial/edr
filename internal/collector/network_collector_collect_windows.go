//go:build windows

package collector

import "context"

func (nc *NetworkCollector) collectWindowsMIB(ctx context.Context) ([]Telemetry, error) {
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	poll, _ := nc.windowsShouldPollUserlandNet()
	if !poll {
		return nil, nil
	}
	rows, err := windowsMIBTCPConnections(maxMIBConnRows)
	if err != nil {
		return nil, err
	}
	nc.scans.Add(1)
	return nc.collectFromConnSlice(rows), nil
}
