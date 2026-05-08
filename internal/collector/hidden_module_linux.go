//go:build linux

package collector

import (
	"bufio"
	"context"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"time"

	"github.com/razatechofficial/edr/internal/config"
	"github.com/razatechofficial/edr/internal/schema"
)

// HiddenModuleSource compares /proc/modules listings with /sys/module (best-effort rootkit heuristic).
type HiddenModuleSource struct {
	endpointID string
	hostname   string
	cfg        config.Config

	emits   atomic.Uint64
	lastRun atomic.Int64
	lastErr atomic.Value // string
}

func NewHiddenModuleSource(endpointID string, cfg config.Config) *HiddenModuleSource {
	h, _ := os.Hostname()
	return &HiddenModuleSource{endpointID: endpointID, hostname: h, cfg: cfg}
}

func (s *HiddenModuleSource) ExportMonitoringHealth() map[string]any {
	src := MonitoringSource{
		Name:          "hidden_module_linux",
		OS:            runtime.GOOS,
		Source:        "proc_sys",
		Status:        "healthy",
		EPSOut:        s.emits.Load(),
		LastEventUnix: s.lastRun.Load(),
	}.ToMap()
	src["enabled"] = s.cfg.Monitoring.LinuxHiddenModule
	if v := s.lastErr.Load(); v != nil {
		if es, ok := v.(string); ok && es != "" {
			src["last_error"] = es
		}
	}
	return src
}

func (s *HiddenModuleSource) Run(ctx context.Context, sink *StreamingSink) error {
	if !s.cfg.Monitoring.LinuxHiddenModule {
		return nil
	}
	t := time.NewTicker(10 * time.Minute)
	defer t.Stop()
	s.scanOnce(ctx, sink)
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
			s.scanOnce(ctx, sink)
		}
	}
}

func (s *HiddenModuleSource) scanOnce(ctx context.Context, sink *StreamingSink) {
	now := time.Now().UTC()
	s.lastRun.Store(now.Unix())
	s.lastErr.Store("")

	procMods, err := readProcModuleNames()
	if err != nil {
		s.lastErr.Store(err.Error())
		return
	}
	sysMods, err := readSysModuleNames()
	if err != nil {
		s.lastErr.Store(err.Error())
		return
	}

	emit := func(kind, name string) {
		s.emits.Add(1)
		pe := &schema.ProcessEvent{
			BaseEvent: schema.BaseEvent{
				SchemaVersion: schema.SchemaVersionV1,
				EventType:     schema.EventProcess,
				EndpointID:    s.endpointID,
				Timestamp:     now,
				Hostname:      s.hostname,
				OS:            runtime.GOOS,
			},
			ProcessName: "posture.hidden_module",
			ProcessPath: "/sys/module/" + name,
			CommandLine: "posture.hidden_module kind=" + kind + " module=" + name,
			Tags:        []string{"rootkit-iocs", "hidden-module", kind},
			Severity:    "high",
		}
		if sink != nil {
			_ = sink.Send(ctx, Telemetry{Process: pe})
		}
	}

	for m := range sysMods {
		if ctx.Err() != nil {
			return
		}
		if !procMods[m] && m != "" {
			emit("sys_not_in_proc", m)
		}
	}
	for m := range procMods {
		if ctx.Err() != nil {
			return
		}
		if !sysMods[m] && m != "" {
			emit("proc_not_in_sys", m)
		}
	}
}

func readProcModuleNames() (map[string]bool, error) {
	f, err := os.Open("/proc/modules")
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return readProcModuleNamesFromReader(f)
}

func readProcModuleNamesFromReader(r io.Reader) (map[string]bool, error) {
	out := map[string]bool{}
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		line := strings.Fields(sc.Text())
		if len(line) == 0 {
			continue
		}
		out[line[0]] = true
	}
	return out, sc.Err()
}

func readSysModuleNames() (map[string]bool, error) {
	ent, err := os.ReadDir("/sys/module")
	if err != nil {
		return nil, err
	}
	return sysModuleNamesFromEntries(ent), nil
}

func sysModuleNamesFromEntries(ent []os.DirEntry) map[string]bool {
	out := map[string]bool{}
	for _, e := range ent {
		name := filepath.Base(e.Name())
		if strings.HasPrefix(name, ".") {
			continue
		}
		out[name] = true
	}
	return out
}
