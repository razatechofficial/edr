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

	"github.com/razatechofficial/edr/internal/schema"
)

// NetworkCollector polls the kernel's TCP/UDP connection tables and emits
// NetworkEvent telemetry for new connections observed since the last Collect.
type NetworkCollector struct {
	endpointID string
	hostname   string
	mu         sync.Mutex
	seen       map[string]struct{}

	scans   atomic.Uint64
	emitted atomic.Uint64
	dropped atomic.Uint64
}

func NewNetworkCollector(endpointID string) *NetworkCollector {
	hostname, _ := os.Hostname()
	return &NetworkCollector{
		endpointID: endpointID,
		hostname:   hostname,
		seen:       make(map[string]struct{}),
	}
}

func (nc *NetworkCollector) Name() string { return "network" }

func (nc *NetworkCollector) Collect(_ context.Context) ([]Telemetry, error) {
	if runtime.GOOS != "linux" && runtime.GOOS != "darwin" {
		return nil, nil
	}
	nc.scans.Add(1)

	var conns []connEntry
	if runtime.GOOS == "linux" {
		conns = append(conns, parseProcNet("/proc/net/tcp", "tcp")...)
		conns = append(conns, parseProcNet("/proc/net/tcp6", "tcp")...)
		conns = append(conns, parseProcNet("/proc/net/udp", "udp")...)
		conns = append(conns, parseProcNet("/proc/net/udp6", "udp")...)
	} else {
		conns = darwinLsofConnections()
	}

	nc.mu.Lock()
	defer nc.mu.Unlock()

	now := time.Now().UTC()
	var out []Telemetry

	for _, c := range conns {
		key := fmt.Sprintf("%s:%s:%d:%s:%d:%d", c.proto, c.srcIP, c.srcPort, c.dstIP, c.dstPort, c.pid)
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
	return out, nil
}

// ExportMonitoringHealth surfaces /proc-net or lsof polling stats.
func (nc *NetworkCollector) ExportMonitoringHealth() map[string]any {
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
	return src.ToMap()
}

type connEntry struct {
	proto   string
	srcIP   string
	srcPort int
	dstIP   string
	dstPort int
	pid     int // non-zero when source provides it (e.g. Darwin lsof)
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
		srcIP, srcPort := parseHexAddr(fields[1])
		dstIP, dstPort := parseHexAddr(fields[2])

		entries = append(entries, connEntry{
			proto:   proto,
			srcIP:   srcIP,
			srcPort: srcPort,
			dstIP:   dstIP,
			dstPort: dstPort,
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


