//go:build darwin

package collector

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/razatechofficial/edr/internal/config"
	"github.com/razatechofficial/edr/internal/schema"
)

// TCCWatchSource polls TCC.db for row-level changes (best-effort).
type TCCWatchSource struct {
	endpointID string
	hostname   string
	cfg        config.Config

	lastMod map[string]time.Time
	// snaps[dbPath][table] -> rowKey -> serialized row
	snaps map[string]map[string]map[string]string

	eventsTotal atomic.Uint64
	lastUnix    atomic.Int64
	readable    atomic.Bool
	active      atomic.Bool
	fsActive    atomic.Bool
	forcePoll   atomic.Bool
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
		snaps:      make(map[string]map[string]map[string]string),
	}
}

func (s *TCCWatchSource) tccPaths() []string {
	home, _ := os.UserHomeDir()
	return []string{
		"/Library/Application Support/com.apple.TCC/TCC.db",
		filepath.Join(home, "Library/Application Support/com.apple.TCC/TCC.db"),
	}
}

func (s *TCCWatchSource) tccWatchDirs() []string {
	var out []string
	seen := map[string]struct{}{}
	for _, p := range s.tccPaths() {
		d := filepath.Dir(p)
		if _, ok := seen[d]; ok {
			continue
		}
		seen[d] = struct{}{}
		out = append(out, d)
	}
	return out
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
	src["tcc_fsnotify_active"] = s.fsActive.Load()
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
	defer s.active.Store(false)

	var watcher *fsnotify.Watcher
	if w, err := fsnotify.NewWatcher(); err == nil {
		watcher = w
		s.fsActive.Store(true)
		defer func() {
			s.fsActive.Store(false)
			_ = watcher.Close()
		}()
		for _, d := range s.tccWatchDirs() {
			_ = watcher.Add(d)
		}
	}

	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	s.poll(ctx, sink)
	for {
		if watcher != nil {
			select {
			case <-ctx.Done():
				return nil
			case <-ticker.C:
				s.poll(ctx, sink)
			case _, ok := <-watcher.Events:
				if ok {
					s.forcePoll.Store(true)
					s.poll(ctx, sink)
				}
			case _, ok := <-watcher.Errors:
				if !ok {
					return nil
				}
				// ignore individual errors — next poll retries
			}
		} else {
			select {
			case <-ctx.Done():
				return nil
			case <-ticker.C:
				s.poll(ctx, sink)
			}
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
		prevT, tok := s.lastMod[p]
		forced := s.forcePoll.Swap(false)
		if !forced && tok && st.ModTime().Equal(prevT) {
			continue
		}
		s.lastMod[p] = st.ModTime()
		tables, err := s.readAllTables(ctx, p)
		if err != nil || len(tables) == 0 {
			continue
		}
		prevSnap, seen := s.snaps[p]
		if !seen {
			s.snaps[p] = tables
			continue
		}
		for table, rows := range tables {
			oldTable := prevSnap[table]
			if oldTable == nil {
				oldTable = map[string]string{}
			}
			for k, v := range rows {
				old, had := oldTable[k]
				if had && old == v {
					continue
				}
				s.eventsTotal.Add(1)
				tag := TCCRowChangeTag(had)
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
					CommandLine: fmt.Sprintf("posture.tcc_change table=%s %s %s=%s", table, tag, k, v),
					Tags:        []string{"posture", "tcc_change", tag, "table:" + table},
				}
				if sink != nil {
					_ = sink.Send(ctx, Telemetry{Process: pe})
				}
			}
		}
		s.snaps[p] = tables
	}
}

func (s *TCCWatchSource) readAllTables(ctx context.Context, dbPath string) (map[string]map[string]string, error) {
	out := map[string]map[string]string{}
	lim := s.cfg.Monitoring.MacosTCCMaxRows
	limitClause := ""
	if lim > 0 {
		limitClause = fmt.Sprintf(" LIMIT %d", lim)
	}
	queries := map[string]string{
		"access": `SELECT printf('%s|%s|%s', ifnull(service,''), ifnull(client,''), ifnull(cast(auth_value as text),'')) FROM access` + limitClause,
		"policies": `SELECT printf('%s|%s|%s', ifnull(service,''), ifnull(client,''), ifnull(cast(policy_id as text),'')) FROM policies` + limitClause,
		"access_overwrite": `SELECT printf('%s|%s|%s', ifnull(service,''), ifnull(client,''), ifnull(cast(auth_value as text),'')) FROM access_overwrite` + limitClause,
		"active_policy": `SELECT printf('%s', ifnull(cast(policy_id as text),'')) FROM active_policy` + limitClause,
	}
	for table, q := range queries {
		rows, err := s.runSQLiteQuery(ctx, dbPath, q, table)
		if err != nil || len(rows) == 0 {
			continue
		}
		out[table] = rows
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no readable tcc tables")
	}
	return out, nil
}

func (s *TCCWatchSource) runSQLiteQuery(ctx context.Context, dbPath, q, table string) (map[string]string, error) {
	cmd := exec.CommandContext(ctx, "sqlite3", "-readonly", dbPath, q)
	out, err := cmd.Output()
	if err != nil {
		return nil, err
	}
	m := make(map[string]string)
	sc := bufio.NewScanner(strings.NewReader(string(out)))
	for sc.Scan() {
		line := sc.Text()
		var key, val string
		switch table {
		case "active_policy":
			key = "policy_id"
			val = strings.TrimSpace(line)
		default:
			parts := strings.SplitN(line, "|", 3)
			if len(parts) < 2 {
				continue
			}
			key = parts[0] + "|" + parts[1]
			val = ""
			if len(parts) > 2 {
				val = parts[2]
			}
		}
		if key == "" && val == "" {
			continue
		}
		if key == "" {
			key = val
		}
		m[key] = val
	}
	return m, sc.Err()
}
