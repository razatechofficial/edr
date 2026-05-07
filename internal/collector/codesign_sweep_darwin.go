//go:build darwin

package collector

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"sync/atomic"
	"time"

	"github.com/razatechofficial/edr/internal/config"
	"github.com/razatechofficial/edr/internal/schema"
)

// CodesignSweepDarwinSource runs periodic codesign verification on running process binaries.
type CodesignSweepDarwinSource struct {
	endpointID string
	hostname   string
	cfg        config.Config

	eventsTotal atomic.Uint64
	lastUnix    atomic.Int64
}

func NewCodesignSweepDarwinSource(endpointID, hostname string, cfg config.Config) *CodesignSweepDarwinSource {
	if hostname == "" {
		hostname, _ = os.Hostname()
	}
	return &CodesignSweepDarwinSource{endpointID: endpointID, hostname: hostname, cfg: cfg}
}

func (s *CodesignSweepDarwinSource) ExportMonitoringHealth() map[string]any {
	src := MonitoringSource{
		Name:          "codesign_sweep",
		OS:            runtime.GOOS,
		Source:        "codesign",
		Status:        "healthy",
		EPSOut:        s.eventsTotal.Load(),
		LastEventUnix: s.lastUnix.Load(),
	}.ToMap()
	src["enabled"] = s.cfg.Monitoring.MacosCodesignSweep
	return src
}

func (s *CodesignSweepDarwinSource) Run(ctx context.Context, sink *StreamingSink) error {
	if !s.cfg.Monitoring.MacosCodesignSweep {
		return nil
	}
	if _, err := exec.LookPath("codesign"); err != nil {
		return nil
	}
	iv := s.cfg.Monitoring.MacosCodesignIntervalSec
	if iv <= 0 {
		iv = 600
	}
	t := time.NewTicker(time.Duration(iv) * time.Second)
	defer t.Stop()
	s.sweep(ctx, sink)
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
			s.sweep(ctx, sink)
		}
	}
}

func (s *CodesignSweepDarwinSource) sweep(ctx context.Context, sink *StreamingSink) {
	now := time.Now().UTC()
	s.lastUnix.Store(now.Unix())
	cmd := exec.CommandContext(ctx, "ps", "-axo", "pid=,command=")
	out, err := cmd.Output()
	if err != nil {
		return
	}
	lines := bytes.Split(out, []byte{'\n'})
	n := 0
	for _, ln := range lines {
		if ctx.Err() != nil {
			return
		}
		if n > 200 {
			break
		}
		fields := strings.Fields(string(ln))
		if len(fields) < 2 {
			continue
		}
		path := fields[1]
		if !strings.HasPrefix(path, "/") {
			continue
		}
		n++
		c := exec.CommandContext(ctx, "codesign", "--verify", "--verbose=2", path)
		if err := c.Run(); err != nil {
			s.eventsTotal.Add(1)
			pe := &schema.ProcessEvent{
				BaseEvent: schema.BaseEvent{
					SchemaVersion: schema.SchemaVersionV1,
					EventType:     schema.EventProcess,
					EndpointID:    s.endpointID,
					Timestamp:     now,
					Hostname:      s.hostname,
					OS:            runtime.GOOS,
				},
				ProcessName: "posture",
				ProcessPath: path,
				CommandLine: "posture.codesign_invalid verify_failed",
				Tags:        []string{"posture", "codesign_invalid"},
				Severity:    "medium",
			}
			if sink != nil {
				_ = sink.Send(ctx, Telemetry{Process: pe})
			}
		}
	}
}
