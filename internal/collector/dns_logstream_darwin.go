//go:build darwin

package collector

import (
	"bufio"
	"context"
	"errors"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/razatechofficial/edr/internal/schema"
)

// LogStreamDNSSource tails unified logging for mDNSResponder/syslog lines that
// look like DNS lookups. It is the userland analogue of Linux eBPF DNS hooks
// and keeps the hot path to a single subprocess (log stream) instead of
// polling scutil or spawning dig.
type LogStreamDNSSource struct {
	endpointID string
	hostname   string

	mu      sync.Mutex
	started bool

	emitted atomic.Uint64
	errs    atomic.Pointer[string]
}

var dnsLogLine = regexp.MustCompile(`(?i)(query|resolve|lookup)\s+([a-z0-9._-]+\.[a-z]{2,})`)

// NewLogStreamDNSSource constructs a source. No network permission is required;
// only stdout from `log stream`.
func NewLogStreamDNSSource(endpointID, hostname string) *LogStreamDNSSource {
	if hostname == "" {
		if h, err := os.Hostname(); err == nil {
			hostname = h
		} else {
			hostname = "unknown"
		}
	}
	return &LogStreamDNSSource{endpointID: endpointID, hostname: hostname}
}

// Run spawns `log stream --style compact --predicate 'subsystem == "com.apple.network.dns"'`
// (when available) or falls back to a broader predicate, and emits NetworkEvent
// rows with Protocol "dns" until ctx is cancelled.
func (l *LogStreamDNSSource) Run(ctx context.Context, sink *StreamingSink) error {
	args := []string{
		"stream",
		"--style", "compact",
		"--predicate",
		`process == "mDNSResponder" OR subsystem == "com.apple.network.dns" OR eventMessage contains "query"`,
	}
	cmd := exec.CommandContext(ctx, "log", args...)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		l.recordError(err)
		return err
	}
	if err := cmd.Start(); err != nil {
		l.recordError(err)
		return err
	}
	l.mu.Lock()
	l.started = true
	l.mu.Unlock()

	defer func() {
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
		l.mu.Lock()
		l.started = false
		l.mu.Unlock()
	}()

	scanner := bufio.NewScanner(stdout)
	scanner.Buffer(make([]byte, 128*1024), 4*1024*1024)
	for scanner.Scan() {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		line := scanner.Text()
		sub := dnsLogLine.FindStringSubmatch(line)
		if len(sub) < 3 {
			continue
		}
		domain := strings.TrimSpace(sub[2])
		if domain == "" {
			continue
		}
		ev := &schema.NetworkEvent{
			BaseEvent: schema.BaseEvent{
				SchemaVersion: schema.SchemaVersionV1,
				EventType:     schema.EventNetwork,
				EndpointID:    l.endpointID,
				Timestamp:     time.Now().UTC(),
				Hostname:      l.hostname,
				OS:            runtime.GOOS,
			},
			PID:       0,
			Protocol:  "dns",
			Domain:    domain,
			DestPt:    53,
			SourceIP:  "127.0.0.1",
			SourcePt:  0,
		}
		if sink.Send(ctx, Telemetry{Network: ev}) {
			l.emitted.Add(1)
			continue
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
	}
	if err := scanner.Err(); err != nil && !errors.Is(err, context.Canceled) {
		l.recordError(err)
		return err
	}
	return nil
}

// ExportMonitoringHealth implements the per-source health interface.
func (l *LogStreamDNSSource) ExportMonitoringHealth() map[string]any {
	src := MonitoringSource{
		Name:   "dns_log_stream_alt",
		OS:     "darwin",
		Source: "log_stream_dns",
		Status: "healthy",
		EPSOut: l.emitted.Load(),
	}
	l.mu.Lock()
	st := l.started
	l.mu.Unlock()
	if !st {
		src.Status = "unavailable"
	}
	if errPtr := l.errs.Load(); errPtr != nil && *errPtr != "" {
		src.LastError = *errPtr
		src.Status = "degraded"
	}
	return src.ToMap()
}

func (l *LogStreamDNSSource) recordError(err error) {
	if err == nil {
		return
	}
	msg := err.Error()
	l.errs.Store(&msg)
}
