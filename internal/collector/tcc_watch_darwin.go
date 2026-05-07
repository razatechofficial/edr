//go:build darwin

package collector

import (
	"bufio"
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

// TCCWatchSource polls TCC.db for row-level changes (best-effort).
type TCCWatchSource struct {
	endpointID string
	hostname   string
	cfg        config.Config

	lastMod map[string]time.Time
	snaps   map[string]map[string]string

	eventsTotal atomic.Uint64
	lastUnix    atomic.Int64
	readable    atomic.Bool
	active      atomic.Bool
}

func NewTCCWatchSource(endpointID, hostname string, cfg config.Config) *TCCWatchSource {
	if hostname == "" {
		hostname, _ = os.Hostname()
	}
	return &TCCWatchSource{
		endpointID: endpointID,
		hostname:   hostname,
		cfg:        cfg,
		lastMod:    make(map[string]time.Time),
		snaps:      make(map[string]map[string]string),
	}
}

func (s *TCCWatchSource) tccPaths() []string {
	home, _ := os.UserHomeDir()
	return []string{
		"/Library/Application Support/com.apple.TCC/TCC.db",
		filepath.Join(home, "Library/Application Support/com.apple.TCC/TCC.db"),
	}
}

func (s *TCCWatchSource) ExportMonitoringHealth() map[string]any {
	src := MonitoringSource{
		Name:          "tcc_watch",
		OS:            runtime.GOOS,
		Source:        "sqlite_poll",
		Status:        "healthy",
		EPSOut:        s.eventsTotal.Load(),
		LastEventUnix: s.lastUnix.Load(),
	}.ToMap()
	src["enabled"] = s.cfg.Monitoring.MacosTCCWatch
	src["tcc_db_watch_active"] = s.active.Load()
	src["tcc_changes_total"] = s.eventsTotal.Load()
	src["tcc_db_readable"] = s.readable.Load()
	return src
}

func (s *TCCWatchSource) Run(ctx context.Context, sink *StreamingSink) error {
	if !s.cfg.Monitoring.MacosTCCWatch {
		return nil
	}
	if _, err := exec.LookPath("sqlite3"); err != nil {
		return nil
	}
	s.active.Store(true)
	t := time.NewTicker(30 * time.Second)
	defer t.Stop()
	s.poll(ctx, sink)
	for {
		select {
		case <-ctx.Done():
			s.active.Store(false)
			return nil
		case <-t.C:
			s.poll(ctx, sink)
		}
	}
}

func (s *TCCWatchSource) poll(ctx context.Context, sink *StreamingSink) {
	now := time.Now().UTC()
	s.lastUnix.Store(now.Unix())
	for _, p := range s.tccPaths() {
		st, err := os.Stat(p)
		if err != nil {
			continue
		}
		s.readable.Store(true)
		prev, ok := s.lastMod[p]
		if ok && st.ModTime().Equal(prev) {
			continue
		}
		s.lastMod[p] = st.ModTime()
		rows, err := s.readAccess(ctx, p)
		if err != nil || len(rows) == 0 {
			continue
		}
		prevSnap, seen := s.snaps[p]
		if !seen {
			s.snaps[p] = rows
			continue
		}
		for k, v := range rows {
			old, had := prevSnap[k]
			if had && old == v {
				continue
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
				ProcessPath: p,
				CommandLine: "posture.tcc_change " + k + "=" + v,
				Tags:        []string{"posture", "tcc_change"},
			}
			if sink != nil {
				_ = sink.Send(ctx, Telemetry{Process: pe})
			}
		}
		s.snaps[p] = rows
	}
}

func (s *TCCWatchSource) readAccess(ctx context.Context, dbPath string) (map[string]string, error) {
	q := `SELECT printf('%s|%s|%s', ifnull(service,''), ifnull(client,''), ifnull(cast(auth_value as text),'')) FROM access LIMIT 2000`
	cmd := exec.CommandContext(ctx, "sqlite3", "-readonly", dbPath, q)
	out, err := cmd.Output()
	if err != nil {
		return nil, err
	}
	m := make(map[string]string)
	sc := bufio.NewScanner(strings.NewReader(string(out)))
	for sc.Scan() {
		line := sc.Text()
		parts := strings.SplitN(line, "|", 3)
		if len(parts) < 2 {
			continue
		}
		key := parts[0] + "|" + parts[1]
		val := ""
		if len(parts) > 2 {
			val = parts[2]
		}
		m[key] = val
	}
	return m, sc.Err()
}
