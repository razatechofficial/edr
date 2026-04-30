//go:build darwin

package collector

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"runtime"
	"sync"
	"sync/atomic"
	"time"
)

// DarwinAuthUnifiedSource tails unified log for ssh/sudo style lines when
// /var/log/system.log is not readable (TCC / Full Disk Access).
type DarwinAuthUnifiedSource struct {
	endpointID string
	hostname   string
	tracker    *LineageTracker

	mu      sync.Mutex
	cmd     *exec.Cmd
	stdout  io.ReadCloser
	started bool

	emitted atomic.Uint64
	errs    atomic.Pointer[string]
}

func NewDarwinAuthUnifiedSource(endpointID string, tracker *LineageTracker) *DarwinAuthUnifiedSource {
	hostname, _ := os.Hostname()
	if hostname == "" {
		hostname = "unknown"
	}
	return &DarwinAuthUnifiedSource{
		endpointID: endpointID,
		hostname:   hostname,
		tracker:    tracker,
	}
}

// Run streams log until ctx is cancelled.
func (s *DarwinAuthUnifiedSource) Run(ctx context.Context, sink *StreamingSink) error {
	cmd := exec.CommandContext(ctx, "log", "stream",
		"--style", "compact",
		"--predicate", `process == "sshd" OR process == "sudo" OR subsystem == "com.apple.opendirectoryd"`,
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
	now := time.Now().UTC()
	for scanner.Scan() {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		line := scanner.Text()
		if ev, ok := parseAuthLine(line, s.endpointID, s.hostname, now); ok {
			if sink.Send(ctx, Telemetry{Auth: &ev}) {
				s.emitted.Add(1)
			}
			continue
		}
	}
	if err := scanner.Err(); err != nil {
		s.recordError(err)
		return err
	}
	return nil
}

// ExportMonitoringHealth implements per-source diagnostics (distinct name until wrapped).
func (s *DarwinAuthUnifiedSource) ExportMonitoringHealth() map[string]any {
	src := MonitoringSource{
		Name:   "darwin_auth_stream",
		OS:     "darwin",
		Source: "log_stream_auth",
		Status: "healthy",
		EPSOut: s.emitted.Load(),
	}
	s.mu.Lock()
	st := s.started
	s.mu.Unlock()
	if !st {
		src.Status = "unavailable"
	}
	if errPtr := s.errs.Load(); errPtr != nil && *errPtr != "" {
		src.LastError = *errPtr
		src.Status = "degraded"
	}
	return src.ToMap()
}

func (s *DarwinAuthUnifiedSource) recordError(err error) {
	if err == nil {
		return
	}
	msg := err.Error()
	s.errs.Store(&msg)
}

type darwinUnifiedAuthPillar struct {
	*streamingRunCollector
}

func newDarwinUnifiedAuthPillar(src *DarwinAuthUnifiedSource, streamMaxEPS int) *darwinUnifiedAuthPillar {
	raw := newStreamingRunCollector("__auth_unified_darwin", 128, streamMaxEPS, src.Run, func() map[string]any {
		return darwinUnifiedAuthPillarHealth(src)
	})
	return &darwinUnifiedAuthPillar{streamingRunCollector: raw}
}

func (d *darwinUnifiedAuthPillar) Name() string { return "auth" }

func darwinUnifiedAuthPillarHealth(src *DarwinAuthUnifiedSource) map[string]any {
	h := src.ExportMonitoringHealth()
	if h == nil {
		return MonitoringSource{Name: "auth", OS: runtime.GOOS, Source: "unified_log", Status: "healthy"}.ToMap()
	}
	h["name"] = "auth"
	h["source"] = "unified_log"
	if _, ok := h["notes"]; !ok {
		h["notes"] = "ssh/sudo via log stream (FDA/TCC workaround)"
	}
	return h
}
