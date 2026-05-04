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
	var probes []string
	defer nc.setOtherProbesLast(probes)

	try := func(name string, fn func(context.Context) []connEntry) []connEntry {
		probes = append(probes, name)
		if conns := fn(ctx); len(conns) > 0 {
			nc.otherNetSource.Store(name)
			return conns
		}
		return nil
	}
	if c := try("proc_net_polling", gatherFromProcNetOther); len(c) > 0 {
		return c
	}
	if c := try("ss_poll", gatherFromSS); len(c) > 0 {
		return c
	}
	if c := try("netstat_poll", gatherFromNetstat); len(c) > 0 {
		return c
	}
	if c := try("lsof_poll", gatherFromLsofNet); len(c) > 0 {
		return c
	}
	nc.otherNetSource.Store("absent")
	return nil
}

func (nc *NetworkCollector) setOtherProbesLast(p []string) {
	if nc == nil {
		return
	}
	nc.otherProbesMu.Lock()
	nc.otherProbesLast = append([]string(nil), p...)
	nc.otherProbesMu.Unlock()
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

func gatherFromSS(ctx context.Context) []connEntry {
	sub, cancel := context.WithTimeout(ctx, 200*time.Millisecond)
	defer cancel()
	cmd := exec.CommandContext(sub, "ss", "-tuan")
	out, err := cmd.Output()
	if err != nil || len(out) == 0 {
		sub2, cancel2 := context.WithTimeout(ctx, 200*time.Millisecond)
		defer cancel2()
		cmd = exec.CommandContext(sub2, "ss", "-tan", "-uan")
		out, err = cmd.Output()
	}
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
		if c, ok := parseSSLine(string(line)); ok {
			conns = append(conns, c)
		}
	}
	return conns
}

func gatherFromLsofNet(ctx context.Context) []connEntry {
	sub, cancel := context.WithTimeout(ctx, 200*time.Millisecond)
	defer cancel()
	cmd := exec.CommandContext(sub, "lsof", "-i", "-n", "-P")
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
		if c, ok := parseLsofInetLine(string(line)); ok {
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
	case "ss_poll":
		src.Source = "ss_poll"
	case "netstat_poll":
		src.Source = "netstat_poll"
	case "lsof_poll":
		src.Source = "lsof_poll"
	default:
		src.Source = "none"
		src.Status = "absent"
		src.LastError = "no_connection_rows"
		src.Notes = "no procfs/ss/netstat/lsof rows on this tick (rare GOOS); see probes_attempted"
	}
	m := src.ToMap()
	nc.otherProbesMu.Lock()
	attempted := append([]string(nil), nc.otherProbesLast...)
	nc.otherProbesMu.Unlock()
	m["probes_attempted"] = attempted
	m["winning_probe"] = v
	if v == "absent" {
		m["reason"] = "all_probes_empty"
	}
	return m
}
