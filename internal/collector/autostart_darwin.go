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

// AutostartDarwinSource enumerates LaunchAgents/Daemons and related persistence.
type AutostartDarwinSource struct {
	endpointID string
	hostname   string
	cfg        config.Config

	eventsTotal atomic.Uint64
	lastUnix    atomic.Int64

	btmMod map[string]time.Time // path -> last seen mtime
}

func NewAutostartDarwinSource(endpointID, hostname string, cfg config.Config) *AutostartDarwinSource {
	if hostname == "" {
		hostname, _ = os.Hostname()
	}
	return &AutostartDarwinSource{
		endpointID: endpointID,
		hostname:   hostname,
		cfg:        cfg,
		btmMod:     make(map[string]time.Time),
	}
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
		"/Library/Apple/System/Library/LaunchDaemons",
		"/Library/Apple/System/Library/LaunchAgents",
		"/Library/StartupItems",
	}
	if home, err := os.UserHomeDir(); err == nil {
		roots = append(roots, filepath.Join(home, "Library/LaunchAgents"))
	}
	for _, r := range roots {
		_ = filepath.WalkDir(r, func(path string, d os.DirEntry, err error) error {
			if err != nil || ctx.Err() != nil {
				return nil
			}
			if d.IsDir() {
				return nil
			}
			if !strings.HasSuffix(strings.ToLower(path), ".plist") {
				return nil
			}
			prog := s.plistProgram(path)
			if prog == "" {
				return nil
			}
			cls := "launchd"
			if strings.Contains(path, "/StartupItems/") {
				cls = "startup_item"
			}
			s.emit(ctx, sink, now, path, "posture.autostart_item program="+prog, cls, nil)
			return nil
		})
	}
	s.scanLoginItems(ctx, sink, now)
	s.scanCronAndPeriodic(ctx, sink, now)
	s.scanBTM(ctx, sink, now)
	s.scanLoginHook(ctx, sink, now)
	s.scanEmond(ctx, sink, now)
}

func (s *AutostartDarwinSource) emit(ctx context.Context, sink *StreamingSink, ts time.Time, path, cmdline, class string, extra []string) {
	s.eventsTotal.Add(1)
	tags := []string{"posture", "autostart", class}
	tags = append(tags, extra...)
	pe := &schema.ProcessEvent{
		BaseEvent: schema.BaseEvent{
			SchemaVersion: schema.SchemaVersionV1,
			EventType:     schema.EventProcess,
			EndpointID:    s.endpointID,
			Timestamp:     ts,
			Hostname:      s.hostname,
			OS:            runtime.GOOS,
		},
		ProcessName: "posture",
		ProcessPath: path,
		CommandLine: cmdline,
		Tags:        tags,
	}
	if sink != nil {
		_ = sink.Send(ctx, Telemetry{Process: pe})
	}
}

func (s *AutostartDarwinSource) scanLoginItems(ctx context.Context, sink *StreamingSink, ts time.Time) {
	if _, err := exec.LookPath("osascript"); err != nil {
		return
	}
	out, err := exec.CommandContext(ctx, "osascript", "-e", `tell application "System Events" to get POSIX path of every login item`).Output()
	if err != nil || len(out) == 0 {
		return
	}
	for _, p := range splitDarwinLoginItemPaths(string(out)) {
		s.emit(ctx, sink, ts, p, "posture.login_item path="+p, "login_item", nil)
	}
}

func (s *AutostartDarwinSource) scanCronAndPeriodic(ctx context.Context, sink *StreamingSink, ts time.Time) {
	dirs := []string{
		"/etc/cron.d",
		"/etc/cron.daily",
		"/etc/cron.hourly",
		"/etc/cron.weekly",
		"/etc/cron.monthly",
		"/etc/crontab",
		"/private/etc/periodic/daily",
		"/private/etc/periodic/weekly",
		"/private/etc/periodic/monthly",
		"/var/at/tabs",
	}
	for _, d := range dirs {
		fi, err := os.Stat(d)
		if err != nil || ctx.Err() != nil {
			continue
		}
		if fi.IsDir() {
			_ = filepath.WalkDir(d, func(path string, de os.DirEntry, err error) error {
				if err != nil || ctx.Err() != nil {
					return nil
				}
				if de.IsDir() {
					return nil
				}
				s.emit(ctx, sink, ts, path, "posture.cron_item path="+path, "cron", nil)
				return nil
			})
		} else {
			s.emit(ctx, sink, ts, d, "posture.cron_item path="+d, "cron", nil)
		}
	}
}

func (s *AutostartDarwinSource) scanBTM(ctx context.Context, sink *StreamingSink, ts time.Time) {
	var paths []string
	if home, err := os.UserHomeDir(); err == nil {
		paths = append(paths, filepath.Join(home, "Library/Application Support/com.apple.backgroundtaskmanagement/BackgroundItems-v3.btm"))
	}
	paths = append(paths, "/var/db/com.apple.backgroundtaskmanagement/BackgroundItems-v3.btm")
	for _, p := range paths {
		st, err := os.Stat(p)
		if err != nil {
			continue
		}
		prev := s.btmMod[p]
		s.btmMod[p] = st.ModTime()
		if prev.IsZero() {
			continue
		}
		if st.ModTime().Equal(prev) {
			continue
		}
		s.emit(ctx, sink, ts, p, "posture.btm_change mtime="+st.ModTime().UTC().Format(time.RFC3339), "btm", nil)
	}
}

func (s *AutostartDarwinSource) scanLoginHook(ctx context.Context, sink *StreamingSink, ts time.Time) {
	if _, err := exec.LookPath("defaults"); err != nil {
		return
	}
	path := `/Library/Preferences/com.apple.loginwindow.plist`
	for _, hook := range []string{"LoginHook", "LogoutHook"} {
		out, err := exec.CommandContext(ctx, "defaults", "read", path, hook).Output()
		if err != nil {
			continue
		}
		val := strings.TrimSpace(string(out))
		if val == "" {
			continue
		}
		s.emit(ctx, sink, ts, path, "posture.login_hook "+hook+"="+val, "login_hook", nil)
	}
}

func (s *AutostartDarwinSource) scanEmond(ctx context.Context, sink *StreamingSink, ts time.Time) {
	dirs := []string{"/etc/emond.d/rules", "/private/var/db/emondClients"}
	for _, d := range dirs {
		_ = filepath.WalkDir(d, func(path string, de os.DirEntry, err error) error {
			if err != nil || ctx.Err() != nil {
				return nil
			}
			if de.IsDir() {
				return nil
			}
			if strings.HasSuffix(strings.ToLower(path), ".plist") {
				s.emit(ctx, sink, ts, path, "posture.emond_rule path="+path, "emond", nil)
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
