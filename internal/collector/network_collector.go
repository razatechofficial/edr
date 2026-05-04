package collector

import (
	"bufio"
	"context"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/razatechofficial/edr/internal/config"
	"github.com/razatechofficial/edr/internal/schema"
)

// NetworkCollector polls the kernel's TCP/UDP connection tables and emits
// NetworkEvent telemetry for new connections observed since the last Collect.
type NetworkCollector struct {
	endpointID string
	hostname   string
	cfg        config.Config
	mu         sync.Mutex
	seen       map[string]struct{}

	scans   atomic.Uint64
	emitted atomic.Uint64
	dropped atomic.Uint64

	// linux_proc_net_pid_enrich: last-tick inode vs PID counts (GOOS=linux only).
	linuxEnrichInodeLast atomic.Uint64
	linuxEnrichPIDLast   atomic.Uint64
	// linuxEnrichLowRateStreak counts consecutive ticks where attribution rate < 5% with enough inodes.
	linuxEnrichLowRateStreak atomic.Uint32

	// otherNetSource records last rare-GOOS winning gather path.
	otherNetSource atomic.Value // string
	otherProbesMu  sync.Mutex
	otherProbesLast []string // last gather probe order (diagnostics)
}

func NewNetworkCollector(endpointID string, cfg config.Config) *NetworkCollector {
	hostname, _ := os.Hostname()
	return &NetworkCollector{
		endpointID: endpointID,
		hostname:   hostname,
		cfg:        cfg,
		seen:       make(map[string]struct{}),
	}
}

func (nc *NetworkCollector) Name() string { return "network" }

func (nc *NetworkCollector) Collect(ctx context.Context) ([]Telemetry, error) {
	if runtime.GOOS == "windows" {
		return nc.collectWindowsMIB(ctx)
	}
	if runtime.GOOS != "linux" && runtime.GOOS != "darwin" {
		return gatherOtherPlatformConnections(ctx, nc)
	}
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	nc.scans.Add(1)

	var conns []connEntry
	if runtime.GOOS == "linux" {
		conns = append(conns, parseProcNet("/proc/net/tcp", "tcp")...)
		conns = append(conns, parseProcNet("/proc/net/tcp6", "tcp")...)
		conns = append(conns, parseProcNet("/proc/net/udp", "udp")...)
		conns = append(conns, parseProcNet("/proc/net/udp6", "udp")...)
		applyLinuxProcNetPIDEnrichIfConfigured(ctx, nc, conns)
	} else {
		conns = darwinLsofConnections()
	}

	return nc.collectFromConnSlice(conns), nil
}

func (nc *NetworkCollector) collectFromConnSlice(conns []connEntry) []Telemetry {
	nc.mu.Lock()
	defer nc.mu.Unlock()

	now := time.Now().UTC()
	var out []Telemetry

	for _, c := range conns {
		key := fmt.Sprintf("%s:%s:%d:%s:%d", c.proto, c.srcIP, c.srcPort, c.dstIP, c.dstPort)
		if c.inode != 0 {
			key += fmt.Sprintf(":ino:%d", c.inode)
		} else if c.pid != 0 {
			key += fmt.Sprintf(":pid:%d", c.pid)
		}
		if _, exists := nc.seen[key]; exists {
			nc.dropped.Add(1)
			continue
		}
		nc.seen[key] = struct{}{}

		if c.dstIP == "0.0.0.0" || c.dstIP == "::" || c.dstIP == "" {
			nc.dropped.Add(1)
			continue
		}

		out = append(out, Telemetry{
			Network: &schema.NetworkEvent{
				BaseEvent: schema.BaseEvent{
					SchemaVersion: schema.SchemaVersionV1,
					EventType:     schema.EventNetwork,
					EndpointID:    nc.endpointID,
					Timestamp:     now,
					Hostname:      nc.hostname,
					OS:            runtime.GOOS,
				},
				PID:      c.pid,
				Protocol: c.proto,
				SourceIP: c.srcIP,
				SourcePt: c.srcPort,
				DestIP:   c.dstIP,
				DestPt:   c.dstPort,
			},
		})
		nc.emitted.Add(1)
	}
	return out
}

// ExportMonitoringHealth surfaces /proc-net or lsof polling stats.
func (nc *NetworkCollector) ExportMonitoringHealth() map[string]any {
	if runtime.GOOS == "windows" {
		return nc.exportNetworkHealthWindows()
	}
	if runtime.GOOS != "linux" && runtime.GOOS != "darwin" {
		return exportOtherPlatformNetworkHealth(nc)
	}
	src := MonitoringSource{
		Name:    "network",
		OS:      runtime.GOOS,
		Source:  "proc_net_polling",
		Status:  "healthy",
		EPSIn:   nc.scans.Load(),
		EPSOut:  nc.emitted.Load(),
		Dropped: nc.dropped.Load(),
	}
	if runtime.GOOS == "darwin" {
		src.Source = "lsof_pid"
	}
	if runtime.GOOS == "linux" && nc.cfg.Monitoring.LinuxProcNetPIDEnrich {
		if src.Notes != "" {
			src.Notes += "; "
		}
		src.Notes += "linux_proc_net_pid_enrich=true: best-effort PID via /proc/*/fd socket inode reverse-map"
		inode := nc.linuxEnrichInodeLast.Load()
		pid := nc.linuxEnrichPIDLast.Load()
		var rate float64
		if inode > 0 {
			rate = float64(pid) / float64(inode)
		}
		m := src.ToMap()
		m["pid_attribution_rate"] = rate
		if inode >= 5 && rate < 0.05 && nc.linuxEnrichLowRateStreak.Load() >= 6 {
			m["auto_promotion_hint"] = "enable_linux_pid_network"
		}
		return m
	}
	return src.ToMap()
}

type connEntry struct {
	proto   string
	srcIP   string
	srcPort int
	dstIP   string
	dstPort int
	pid     int    // non-zero when source provides it (e.g. Darwin lsof, Linux inode map)
	inode   uint64 // Linux /proc/net inode when parsed (optional)
}

// parseProcNet reads /proc/net/tcp or /proc/net/udp and extracts connections.
func parseProcNet(path, proto string) []connEntry {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()

	var entries []connEntry
	scanner := bufio.NewScanner(f)
	scanner.Scan() // skip header

	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 4 {
			continue
		}
		// Data rows start with "sl_index:" (e.g. "12:"); skip header / garbage lines.
		if len(fields[0]) < 1 || fields[0][0] < '0' || fields[0][0] > '9' {
			continue
		}
		srcIP, srcPort := parseHexAddr(fields[1])
		dstIP, dstPort := parseHexAddr(fields[2])
		var inode uint64
		if len(fields) >= 10 {
			inode, _ = strconv.ParseUint(fields[9], 10, 64)
		}

		entries = append(entries, connEntry{
			proto:   proto,
			srcIP:   srcIP,
			srcPort: srcPort,
			dstIP:   dstIP,
			dstPort: dstPort,
			inode:   inode,
		})
	}
	return entries
}

func parseHexAddr(s string) (string, int) {
	parts := strings.SplitN(s, ":", 2)
	if len(parts) != 2 {
		return "", 0
	}

	port, _ := strconv.ParseUint(parts[1], 16, 16)

	hexIP := parts[0]
	switch len(hexIP) {
	case 8:
		b, err := hex.DecodeString(hexIP)
		if err != nil || len(b) != 4 {
			return hexIP, int(port)
		}
		ip := net.IPv4(b[3], b[2], b[1], b[0])
		return ip.String(), int(port)
	case 32:
		b, err := hex.DecodeString(hexIP)
		if err != nil || len(b) != 16 {
			return hexIP, int(port)
		}
		for i := 0; i < 16; i += 4 {
			b[i], b[i+3] = b[i+3], b[i]
			b[i+1], b[i+2] = b[i+2], b[i+1]
		}
		ip := net.IP(b)
		return ip.String(), int(port)
	default:
		return hexIP, int(port)
	}
}
