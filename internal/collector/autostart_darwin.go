//go:build darwin

package collector

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"time"

	"github.com/razatechofficial/edr/internal/config"
	"github.com/razatechofficial/edr/internal/schema"
)

// AutostartDarwinSource enumerates LaunchAgents/Daemons and related paths.
type AutostartDarwinSource struct {
	endpointID string
	hostname   string
	cfg        config.Config

	eventsTotal atomic.Uint64
	lastUnix    atomic.Int64
}

func NewAutostartDarwinSource(endpointID, hostname string, cfg config.Config) *AutostartDarwinSource {
	if hostname == "" {
		hostname, _ = os.Hostname()
	}
	return &AutostartDarwinSource{endpointID: endpointID, hostname: hostname, cfg: cfg}
}

func (s *AutostartDarwinSource) ExportMonitoringHealth() map[string]any {
	src := MonitoringSource{
		Name:          "autostart_darwin",
		OS:            runtime.GOOS,
		Source:        "fs",
		Status:        "healthy",
		EPSOut:        s.eventsTotal.Load(),
		LastEventUnix: s.lastUnix.Load(),
	}.ToMap()
	src["enabled"] = s.cfg.Monitoring.MacosAutostartEnumerator
	return src
}

func (s *AutostartDarwinSource) Run(ctx context.Context, sink *StreamingSink) error {
	if !s.cfg.Monitoring.MacosAutostartEnumerator {
		return nil
	}
	t := time.NewTicker(15 * time.Minute)
	defer t.Stop()
	s.scan(ctx, sink)
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
			s.scan(ctx, sink)
		}
	}
}

func (s *AutostartDarwinSource) scan(ctx context.Context, sink *StreamingSink) {
	now := time.Now().UTC()
	s.lastUnix.Store(now.Unix())
	roots := []string{
		"/Library/LaunchDaemons",
		"/Library/LaunchAgents",
		"/System/Library/LaunchDaemons",
		"/System/Library/LaunchAgents",
	}
	if home, err := os.UserHomeDir(); err == nil {
		roots = append(roots, filepath.Join(home, "Library/LaunchAgents"))
	}
	for _, r := range roots {
		_ = filepath.WalkDir(r, func(path string, d os.DirEntry, err error) error {
			if err != nil || ctx.Err() != nil {
				return nil
			}
			if d.IsDir() || !strings.HasSuffix(strings.ToLower(path), ".plist") {
				return nil
			}
			prog := s.plistProgram(path)
			if prog == "" {
				return nil
			}
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
				CommandLine: "posture.autostart_item program=" + prog,
				Tags:        []string{"posture", "autostart"},
			}
			if sink != nil {
				_ = sink.Send(ctx, Telemetry{Process: pe})
			}
			return nil
		})
	}
}

func (s *AutostartDarwinSource) plistProgram(path string) string {
	if _, err := exec.LookPath("plutil"); err != nil {
		return ""
	}
	out, err := exec.Command("plutil", "-p", path).Output()
	if err != nil {
		return ""
	}
	text := string(out)
	var prog string
	var args bool
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if strings.Contains(line, `"Program"`) && strings.Contains(line, "=>") {
			parts := strings.SplitN(line, "=>", 2)
			if len(parts) == 2 {
				prog = strings.Trim(strings.TrimSpace(parts[1]), `"`)
			}
		}
		if strings.Contains(line, `"ProgramArguments"`) {
			args = true
			continue
		}
		if args && prog == "" && strings.HasPrefix(line, "0 =>") {
			parts := strings.SplitN(line, "=>", 2)
			if len(parts) == 2 {
				prog = strings.Trim(strings.TrimSpace(parts[1]), `"`)
				break
			}
		}
	}
	return prog
}
