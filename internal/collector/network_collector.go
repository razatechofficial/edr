package collector

import (
	"bufio"
	"context"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/razatechofficial/edr/internal/schema"
)

var execCmd = exec.Command

// NetworkCollector polls the kernel's TCP/UDP connection tables and emits
// NetworkEvent telemetry for new connections observed since the last Collect.
type NetworkCollector struct {
	endpointID string
	hostname   string
	mu         sync.Mutex
	seen       map[string]struct{}
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

	var conns []connEntry
	if runtime.GOOS == "linux" {
		conns = append(conns, parseProcNet("/proc/net/tcp", "tcp")...)
		conns = append(conns, parseProcNet("/proc/net/tcp6", "tcp")...)
		conns = append(conns, parseProcNet("/proc/net/udp", "udp")...)
		conns = append(conns, parseProcNet("/proc/net/udp6", "udp")...)
	} else {
		conns = parseLsof()
	}

	nc.mu.Lock()
	defer nc.mu.Unlock()

	now := time.Now().UTC()
	var out []Telemetry

	for _, c := range conns {
		key := fmt.Sprintf("%s:%s:%d:%s:%d", c.proto, c.srcIP, c.srcPort, c.dstIP, c.dstPort)
		if _, exists := nc.seen[key]; exists {
			continue
		}
		nc.seen[key] = struct{}{}

		if c.dstIP == "0.0.0.0" || c.dstIP == "::" || c.dstIP == "" {
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
				Protocol: c.proto,
				SourceIP: c.srcIP,
				SourcePt: c.srcPort,
				DestIP:   c.dstIP,
				DestPt:   c.dstPort,
			},
		})
	}
	return out, nil
}

type connEntry struct {
	proto   string
	srcIP   string
	srcPort int
	dstIP   string
	dstPort int
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

// parseLsof extracts network connections on macOS using netstat -an.
func parseLsof() []connEntry {
	return parseNetstat()
}

func parseNetstat() []connEntry {
	out, err := execCommand("netstat", "-an", "-p", "tcp")
	if err != nil {
		return nil
	}
	entries := parseNetstatOutput(string(out), "tcp")

	outUDP, err := execCommand("netstat", "-an", "-p", "udp")
	if err == nil {
		entries = append(entries, parseNetstatOutput(string(outUDP), "udp")...)
	}
	return entries
}

func parseNetstatOutput(output, proto string) []connEntry {
	var entries []connEntry
	for _, line := range strings.Split(output, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 5 {
			continue
		}
		if fields[0] != "tcp4" && fields[0] != "tcp6" && fields[0] != "udp4" && fields[0] != "udp6" {
			continue
		}

		srcIP, srcPort := splitHostPort(fields[3])
		dstIP, dstPort := splitHostPort(fields[4])

		if srcIP == "" || dstIP == "" {
			continue
		}

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

func splitHostPort(addr string) (string, int) {
	lastDot := strings.LastIndex(addr, ".")
	if lastDot < 0 {
		return addr, 0
	}
	host := addr[:lastDot]
	portStr := addr[lastDot+1:]
	if portStr == "*" {
		return host, 0
	}
	port, _ := strconv.Atoi(portStr)
	return host, port
}

func execCommand(name string, args ...string) ([]byte, error) {
	cmd := execCmd(name, args...)
	return cmd.Output()
}
