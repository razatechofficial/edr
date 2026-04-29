//go:build darwin

package collector

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/razatechofficial/edr/internal/schema"
)

// DarwinNetworkSource attributes sockets to pids without cgo by spawning
// `lsof -i -n -P -F pcfnTL` once per snapshot and parsing its compact field
// output. This mirrors the proc_pidfdinfo approach Wazuh uses on macOS but
// avoids the Endpoint Security entitlement requirement and stays cgo-free.
//
// We rely on lsof being present (it ships in /usr/sbin on every macOS) and
// dedupe via a bounded EventDeduper so churn does not blow memory.
type DarwinNetworkSource struct {
	endpointID string
	hostname   string
	tracker    *LineageTracker

	mu      sync.Mutex // guards: dedup
	dedup   *EventDeduper

	scans   atomic.Uint64
	emitted atomic.Uint64
	skipped atomic.Uint64
	errs    atomic.Pointer[string]
}

// NewDarwinNetworkSource constructs a source that uses lsof to enumerate
// pid-attributed sockets.
func NewDarwinNetworkSource(endpointID, hostname string, tracker *LineageTracker) *DarwinNetworkSource {
	if hostname == "" {
		if h, err := os.Hostname(); err == nil {
			hostname = h
		} else {
			hostname = "unknown"
		}
	}
	return &DarwinNetworkSource{
		endpointID: endpointID,
		hostname:   hostname,
		tracker:    tracker,
		dedup:      NewEventDeduper(4096, 30*time.Second),
	}
}

// Snapshot runs lsof and emits NetworkEvent telemetry for each pid-attributed
// socket not seen in the dedup window.
func (s *DarwinNetworkSource) Snapshot(ctx context.Context) ([]Telemetry, error) {
	s.scans.Add(1)
	cmd := exec.CommandContext(ctx, "lsof", "-i", "-n", "-P", "-F", "pcfTPn")
	cmd.Stderr = nil
	out, err := cmd.Output()
	if err != nil {
		s.recordError(err)
		return nil, fmt.Errorf("lsof: %w", err)
	}
	now := time.Now().UTC()
	telems := make([]Telemetry, 0, 16)

	var (
		pid     int
		comm    string
		proto   string
	)
	sc := bufio.NewScanner(strings.NewReader(string(out)))
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	for sc.Scan() {
		line := sc.Text()
		if len(line) < 1 {
			continue
		}
		switch line[0] {
		case 'p':
			if v, err := strconv.Atoi(line[1:]); err == nil {
				pid = v
				comm = ""
				proto = ""
			}
		case 'c':
			comm = line[1:]
		case 'P':
			proto = strings.ToLower(line[1:])
		case 'n':
			srcIP, srcPort, dstIP, dstPort, ok := parseLsofConn(line[1:])
			if !ok {
				continue
			}
			key := proto + "|" + strconv.Itoa(pid) + "|" + srcIP + ":" + strconv.Itoa(srcPort) + "->" + dstIP + ":" + strconv.Itoa(dstPort)
			if !s.dedup.ShouldEmit(key, 30*time.Second) {
				s.skipped.Add(1)
				continue
			}
			if s.tracker != nil && pid > 0 {
				s.tracker.Upsert(LineageEntry{PID: uint32(pid), Comm: comm})
			}
			ne := &schema.NetworkEvent{
				BaseEvent: schema.BaseEvent{
					SchemaVersion: schema.SchemaVersionV1,
					EventType:     schema.EventNetwork,
					EndpointID:    s.endpointID,
					Timestamp:     now,
					Hostname:      s.hostname,
					OS:            runtime.GOOS,
				},
				PID:      pid,
				Protocol: proto,
				SourceIP: srcIP,
				SourcePt: srcPort,
				DestIP:   dstIP,
				DestPt:   dstPort,
			}
			telems = append(telems, Telemetry{Network: ne})
			s.emitted.Add(1)
		}
	}
	if err := sc.Err(); err != nil {
		s.recordError(err)
	}
	return telems, nil
}

// parseLsofConn parses an `n`-prefixed lsof connection field. Examples:
//   "192.168.1.5:54321->10.0.0.1:443"  - established
//   "*:8080"                            - listening
//   "[::1]:80->[::1]:55444"             - v6
func parseLsofConn(s string) (srcIP string, srcPort int, dstIP string, dstPort int, ok bool) {
	parts := strings.SplitN(s, "->", 2)
	srcIP, srcPort, ok = splitLsofHostPort(parts[0])
	if !ok {
		return
	}
	if len(parts) == 2 {
		dstIP, dstPort, ok = splitLsofHostPort(parts[1])
		if !ok {
			return
		}
	}
	return
}

func splitLsofHostPort(s string) (host string, port int, ok bool) {
	if s == "" {
		return "", 0, false
	}
	if s[0] == '[' { // IPv6
		end := strings.Index(s, "]:")
		if end < 0 {
			return "", 0, false
		}
		host = s[1:end]
		p, err := strconv.Atoi(s[end+2:])
		if err != nil {
			return "", 0, false
		}
		return host, p, true
	}
	colon := strings.LastIndexByte(s, ':')
	if colon <= 0 || colon == len(s)-1 {
		return "", 0, false
	}
	host = s[:colon]
	if host == "*" {
		host = ""
	}
	p, err := strconv.Atoi(s[colon+1:])
	if err != nil {
		return "", 0, false
	}
	return host, p, true
}

// ExportMonitoringHealth implements the per-source health interface.
func (s *DarwinNetworkSource) ExportMonitoringHealth() map[string]any {
	src := MonitoringSource{
		Name:    "network",
		OS:      "darwin",
		Source:  "lsof",
		Status:  "healthy",
		EPSIn:   s.scans.Load(),
		EPSOut:  s.emitted.Load(),
		Dropped: s.skipped.Load(),
	}
	if errPtr := s.errs.Load(); errPtr != nil && *errPtr != "" {
		src.LastError = *errPtr
		src.Status = "degraded"
	}
	return src.ToMap()
}

func (s *DarwinNetworkSource) recordError(err error) {
	if err == nil {
		return
	}
	msg := err.Error()
	s.errs.Store(&msg)
}
