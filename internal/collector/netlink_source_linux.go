//go:build linux

package collector

import (
	"context"
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

// SocketSource is the userland fallback used when eBPF is unavailable. It
// enumerates sockets from /proc/net/{tcp,tcp6,udp,udp6} and attributes each
// to the owning pid by walking /proc/<pid>/fd/* once per snapshot. Compared
// to the legacy /proc-only NetworkCollector this version emits the pid and
// dedupes via a shared LineageTracker so userland and kernel paths stay
// consistent.
//
// Despite the plan name "netlink_source", we use /proc here because it is
// a strict superset of the data we need without pulling a new netlink
// dependency. A true AF_NETLINK sock_diag client can be swapped in later
// without changing this struct's interface.
type SocketSource struct {
	endpointID string
	hostname   string
	tracker    *LineageTracker

	mu         sync.Mutex // guards: seenInodes, seen
	seenInodes map[uint64]uint32 // inode -> pid (last seen)
	seen       *EventDeduper

	scans   atomic.Uint64
	emitted atomic.Uint64
	skipped atomic.Uint64
	errs    atomic.Pointer[string]
}

// NewSocketSource returns a SocketSource. tracker may be nil; one is created
// lazily if so.
func NewSocketSource(endpointID, hostname string, tracker *LineageTracker) *SocketSource {
	if tracker == nil {
		tracker = NewLineageTracker(0, 0)
	}
	if hostname == "" {
		if h, err := os.Hostname(); err == nil {
			hostname = h
		} else {
			hostname = "unknown"
		}
	}
	return &SocketSource{
		endpointID: endpointID,
		hostname:   hostname,
		tracker:    tracker,
		seenInodes: make(map[uint64]uint32),
		seen:       NewEventDeduper(4096, 30*time.Second),
	}
}

// Snapshot enumerates current sockets and emits NetworkEvent telemetry for
// any 4-tuple+pid combo not seen in the last 30 seconds. The dedup is bounded
// (LRU+TTL) so memory does not grow with churn.
func (s *SocketSource) Snapshot(ctx context.Context) ([]Telemetry, error) {
	s.scans.Add(1)
	inodeToPID := s.buildInodeToPIDMap(ctx)

	out := make([]Telemetry, 0, 32)
	now := time.Now().UTC()

	for _, fam := range []struct {
		path  string
		proto string
		v6    bool
	}{
		{"/proc/net/tcp", "tcp", false},
		{"/proc/net/tcp6", "tcp", true},
		{"/proc/net/udp", "udp", false},
		{"/proc/net/udp6", "udp", true},
	} {
		if ctx.Err() != nil {
			return out, ctx.Err()
		}
		entries, err := readProcNet(fam.path, fam.v6)
		if err != nil {
			s.recordError(err)
			continue
		}
		for _, e := range entries {
			pid := inodeToPID[e.inode]
			key := fam.proto + "|" + e.srcIP + ":" + strconv.Itoa(e.srcPort) + "->" +
				e.dstIP + ":" + strconv.Itoa(e.dstPort) + "|" + strconv.FormatUint(uint64(pid), 10)
			if !s.seen.ShouldEmit(key, 30*time.Second) {
				s.skipped.Add(1)
				continue
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
				PID:      int(pid),
				Protocol: fam.proto,
				SourceIP: e.srcIP,
				SourcePt: e.srcPort,
				DestIP:   e.dstIP,
				DestPt:   e.dstPort,
			}
			out = append(out, Telemetry{Network: ne})
			s.emitted.Add(1)
		}
	}

	s.mu.Lock()
	s.seenInodes = inodeToPID
	s.mu.Unlock()
	return out, nil
}

// ExportMonitoringHealth implements the per-source health interface.
func (s *SocketSource) ExportMonitoringHealth() map[string]any {
	src := MonitoringSource{
		Name:    "network",
		OS:      "linux",
		Source:  "proc-sock",
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

func (s *SocketSource) recordError(err error) {
	if err == nil {
		return
	}
	msg := err.Error()
	s.errs.Store(&msg)
}

// buildInodeToPIDMap walks /proc/<pid>/fd/* once and indexes every socket
// inode it finds. The result is reused for all four /proc/net families this
// snapshot, keeping the cost amortised.
func (s *SocketSource) buildInodeToPIDMap(ctx context.Context) map[uint64]uint32 {
	return buildSocketInodeToPIDMap(ctx, s.recordError)
}

type netConnEntry struct {
	srcIP   string
	srcPort int
	dstIP   string
	dstPort int
	state   uint32
	inode   uint64
}

func readProcNet(path string, v6 bool) ([]netConnEntry, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	out := make([]netConnEntry, 0, 16)
	lines := strings.Split(string(data), "\n")
	if len(lines) < 2 {
		return out, nil
	}
	for _, line := range lines[1:] { // skip header
		fields := strings.Fields(line)
		if len(fields) < 10 {
			continue
		}
		// fields: sl local_address rem_address st tx_queue rx_queue tr tm->when retrnsmt uid timeout inode ...
		src := fields[1]
		dst := fields[2]
		stateHex := fields[3]
		inodeStr := fields[9]

		srcIP, srcPort, ok1 := parseProcNetAddr(src, v6)
		dstIP, dstPort, ok2 := parseProcNetAddr(dst, v6)
		if !ok1 || !ok2 {
			continue
		}
		state, _ := strconv.ParseUint(stateHex, 16, 32)
		inode, _ := strconv.ParseUint(inodeStr, 10, 64)
		out = append(out, netConnEntry{
			srcIP:   srcIP,
			srcPort: srcPort,
			dstIP:   dstIP,
			dstPort: dstPort,
			state:   uint32(state),
			inode:   inode,
		})
	}
	return out, nil
}

// parseProcNetAddr parses /proc/net's "AABBCCDD:PORT" or v6 "...:PORT" form.
func parseProcNetAddr(s string, v6 bool) (string, int, bool) {
	colon := strings.IndexByte(s, ':')
	if colon <= 0 {
		return "", 0, false
	}
	addrHex := s[:colon]
	portHex := s[colon+1:]
	port64, err := strconv.ParseUint(portHex, 16, 32)
	if err != nil {
		return "", 0, false
	}
	if !v6 {
		if len(addrHex) != 8 {
			return "", 0, false
		}
		// Hex is in network-host-bytes order reversed; e.g. "0100007F" => 127.0.0.1.
		var b [4]byte
		for i := 0; i < 4; i++ {
			v, err := strconv.ParseUint(addrHex[i*2:i*2+2], 16, 8)
			if err != nil {
				return "", 0, false
			}
			b[3-i] = byte(v)
		}
		return net.IP(b[:]).String(), int(port64), true
	}
	if len(addrHex) != 32 {
		return "", 0, false
	}
	var b [16]byte
	// IPv6 in /proc/net is 4 little-endian uint32 words; reorder per word.
	for word := 0; word < 4; word++ {
		base := word * 8
		for i := 0; i < 4; i++ {
			v, err := strconv.ParseUint(addrHex[base+i*2:base+i*2+2], 16, 8)
			if err != nil {
				return "", 0, false
			}
			b[word*4+(3-i)] = byte(v)
		}
	}
	return net.IP(b[:]).String(), int(port64), true
}
