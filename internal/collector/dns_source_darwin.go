//go:build darwin

package collector

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
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

// DarwinDNSSource consumes the macOS unified-log DNS subsystem via
//    log stream --predicate 'subsystem == "com.apple.mDNSResponder"' --style ndjson
// This is the same source Apple's own profiler uses, runs without ESF
// entitlements, and yields a fairly low-rate stream (~tens of msgs/s under
// load) so memory pressure stays bounded.
//
// Like the journald source we keep this cgo-free by spawning the system
// command exactly once at startup; ctx cancellation kills the subprocess and
// the goroutine drains, so there is no leak path.
type DarwinDNSSource struct {
	endpointID string
	hostname   string
	tracker    *LineageTracker

	mu      sync.Mutex // guards: cmd, started
	cmd     *exec.Cmd
	stdout  io.ReadCloser
	started bool

	emitted atomic.Uint64
	errs    atomic.Pointer[string]
}

// NewDarwinDNSSource builds a DNS source.
func NewDarwinDNSSource(endpointID, hostname string, tracker *LineageTracker) *DarwinDNSSource {
	if hostname == "" {
		if h, err := os.Hostname(); err == nil {
			hostname = h
		} else {
			hostname = "unknown"
		}
	}
	return &DarwinDNSSource{
		endpointID: endpointID,
		hostname:   hostname,
		tracker:    tracker,
	}
}

// Run streams DNS messages until ctx is cancelled.
func (s *DarwinDNSSource) Run(ctx context.Context, sink *StreamingSink) error {
	cmd := exec.CommandContext(ctx, "log", "stream",
		"--predicate", `subsystem == "com.apple.mDNSResponder" AND (eventMessage CONTAINS "Query " OR eventMessage CONTAINS "Resolve")`,
		"--style", "ndjson",
		"--info",
	)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		s.recordError(err)
		return fmt.Errorf("log stream stdout: %w", err)
	}
	if err := cmd.Start(); err != nil {
		s.recordError(err)
		return fmt.Errorf("log stream start: %w", err)
	}
	s.mu.Lock()
	s.cmd = cmd
	s.stdout = stdout
	s.started = true
	s.mu.Unlock()

	defer func() {
		s.mu.Lock()
		s.started = false
		s.mu.Unlock()
		_ = stdout.Close()
		_ = cmd.Wait()
	}()

	scanner := bufio.NewScanner(stdout)
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)
	for scanner.Scan() {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		s.dispatchLine(ctx, scanner.Bytes(), sink)
	}
	if err := scanner.Err(); err != nil {
		s.recordError(err)
		return err
	}
	return nil
}

func (s *DarwinDNSSource) dispatchLine(ctx context.Context, line []byte, sink *StreamingSink) {
	var entry map[string]any
	if err := json.Unmarshal(line, &entry); err != nil {
		return
	}
	msg, _ := entry["eventMessage"].(string)
	if msg == "" {
		return
	}
	domain := extractDNSQuery(msg)
	if domain == "" {
		return
	}
	pid := uint32(0)
	if v, ok := entry["processID"].(float64); ok {
		pid = uint32(v)
	} else if pidStr, ok := entry["processID"].(string); ok {
		if p, err := strconv.ParseUint(pidStr, 10, 32); err == nil {
			pid = uint32(p)
		}
	}
	if s.tracker != nil && pid != 0 {
		s.tracker.Upsert(LineageEntry{PID: pid})
	}
	ne := &schema.NetworkEvent{
		BaseEvent: schema.BaseEvent{
			SchemaVersion: schema.SchemaVersionV1,
			EventType:     schema.EventNetwork,
			EndpointID:    s.endpointID,
			Timestamp:     time.Now().UTC(),
			Hostname:      s.hostname,
			OS:            runtime.GOOS,
		},
		PID:      int(pid),
		Protocol: "dns",
		Domain:   domain,
	}
	if sink.Send(ctx, Telemetry{Network: ne}) {
		s.emitted.Add(1)
	}
}

// extractDNSQuery picks a domain out of mDNSResponder messages such as
// "Query: example.com (AAAA)" or "Resolve: 1 example.com".
func extractDNSQuery(msg string) string {
	for _, prefix := range []string{"Query", "Resolve"} {
		i := strings.Index(msg, prefix)
		if i < 0 {
			continue
		}
		rest := msg[i+len(prefix):]
		rest = strings.TrimLeft(rest, ": ")
		fields := strings.Fields(rest)
		// Walk fields; the domain is the first dotted token.
		for _, f := range fields {
			candidate := strings.Trim(f, "()")
			if strings.Contains(candidate, ".") && !strings.ContainsRune(candidate, ' ') {
				return strings.ToLower(candidate)
			}
		}
	}
	return ""
}

// ExportMonitoringHealth implements the per-source health interface.
func (s *DarwinDNSSource) ExportMonitoringHealth() map[string]any {
	src := MonitoringSource{
		Name:   "dns_unified_log",
		OS:     "darwin",
		Source: "log-stream",
		Status: "healthy",
		EPSOut: s.emitted.Load(),
	}
	if !s.started {
		src.Status = "unavailable"
	}
	if errPtr := s.errs.Load(); errPtr != nil && *errPtr != "" {
		src.LastError = *errPtr
		src.Status = "degraded"
	}
	return src.ToMap()
}

func (s *DarwinDNSSource) recordError(err error) {
	if err == nil {
		return
	}
	msg := err.Error()
	s.errs.Store(&msg)
}
