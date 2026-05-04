//go:build !linux && !darwin && !windows

package collector

import (
	"bytes"
	"context"
	"os/exec"
	"runtime"
	"time"
)

func gatherOtherPlatformConnections(ctx context.Context, nc *NetworkCollector) ([]Telemetry, error) {
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	nc.scans.Add(1)
	conns := gatherOtherConnEntries(ctx, nc)
	return nc.collectFromConnSlice(conns), nil
}

func gatherOtherConnEntries(ctx context.Context, nc *NetworkCollector) []connEntry {
	if conns := gatherFromProcNetOther(ctx); len(conns) > 0 {
		nc.otherNetSource.Store("proc_net_polling")
		return conns
	}
	if conns := gatherFromNetstat(ctx); len(conns) > 0 {
		nc.otherNetSource.Store("netstat_poll")
		return conns
	}
	nc.otherNetSource.Store("absent")
	return nil
}

func gatherFromProcNetOther(ctx context.Context) []connEntry {
	if ctx.Err() != nil {
		return nil
	}
	var out []connEntry
	for _, spec := range []struct {
		path  string
		proto string
	}{
		{"/proc/net/tcp", "tcp"},
		{"/proc/net/tcp6", "tcp"},
		{"/proc/net/udp", "udp"},
		{"/proc/net/udp6", "udp"},
	} {
		if ctx.Err() != nil {
			return out
		}
		out = append(out, parseProcNet(spec.path, spec.proto)...)
	}
	return out
}

func gatherFromNetstat(ctx context.Context) []connEntry {
	sub, cancel := context.WithTimeout(ctx, 200*time.Millisecond)
	defer cancel()
	cmd := exec.CommandContext(sub, "netstat", "-an")
	out, err := cmd.Output()
	if err != nil || len(out) == 0 {
		return nil
	}
	if len(out) > 256*1024 {
		out = out[:256*1024]
	}
	var conns []connEntry
	for _, line := range bytes.Split(out, []byte{'\n'}) {
		if ctx.Err() != nil {
			break
		}
		if c, ok := parseNetstatLine(string(line)); ok {
			conns = append(conns, c)
		}
	}
	return conns
}

func exportOtherPlatformNetworkHealth(nc *NetworkCollector) map[string]any {
	v := "absent"
	if x := nc.otherNetSource.Load(); x != nil {
		if s, ok := x.(string); ok && s != "" {
			v = s
		}
	}
	src := MonitoringSource{
		Name:    "network",
		OS:      runtime.GOOS,
		Status:  "healthy",
		EPSIn:   nc.scans.Load(),
		EPSOut:  nc.emitted.Load(),
		Dropped: nc.dropped.Load(),
	}
	switch v {
	case "proc_net_polling":
		src.Source = "proc_net_polling"
	case "netstat_poll":
		src.Source = "netstat_poll"
	default:
		src.Source = "none"
		src.Status = "absent"
		src.Notes = "no procfs/netstat connection rows resolved on this tick (rare GOOS)"
	}
	return src.ToMap()
}
