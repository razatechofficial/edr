//go:build windows

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
	"golang.org/x/sys/windows/registry"
)

// AutorunsLiteSource enumerates a small set of high-signal persistence locations.
type AutorunsLiteSource struct {
	endpointID string
	hostname   string
	cfg        config.Config

	eventsTotal atomic.Uint64
	lastUnix    atomic.Int64
}

func NewAutorunsLiteSource(endpointID, hostname string, cfg config.Config) *AutorunsLiteSource {
	if hostname == "" {
		hostname, _ = os.Hostname()
	}
	return &AutorunsLiteSource{endpointID: endpointID, hostname: hostname, cfg: cfg}
}

func (s *AutorunsLiteSource) ExportMonitoringHealth() map[string]any {
	src := MonitoringSource{
		Name:          "autoruns_lite",
		OS:            runtime.GOOS,
		Source:        "registry",
		Status:        "healthy",
		EPSOut:        s.eventsTotal.Load(),
		LastEventUnix: s.lastUnix.Load(),
	}.ToMap()
	src["enabled"] = s.cfg.Monitoring.WindowsAutorunsLite
	return src
}

func (s *AutorunsLiteSource) Run(ctx context.Context, sink *StreamingSink) error {
	if !s.cfg.Monitoring.WindowsAutorunsLite {
		return nil
	}
	iv := s.cfg.Monitoring.WindowsAutorunsIntervalSec
	if iv <= 0 {
		iv = 300
	}
	t := time.NewTicker(time.Duration(iv) * time.Second)
	defer t.Stop()
	s.enumerate(ctx, sink)
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
			s.enumerate(ctx, sink)
		}
	}
}

func (s *AutorunsLiteSource) enumerate(ctx context.Context, sink *StreamingSink) {
	now := time.Now().UTC()
	s.lastUnix.Store(now.Unix())

	runKeys := []struct {
		root registry.Key
		path string
	}{
		{registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows\CurrentVersion\Run`},
		{registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce`},
		{registry.CURRENT_USER, `SOFTWARE\Microsoft\Windows\CurrentVersion\Run`},
		{registry.CURRENT_USER, `SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce`},
		{registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows\CurrentVersion\RunServices`},
		{registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows\CurrentVersion\RunServicesOnce`},
	}
	for _, rk := range runKeys {
		s.emitRegistryValues(ctx, sink, rk.root, rk.path, "run_key", now)
	}

	s.emitIFEO(ctx, sink, now)
	s.emitSchtasks(ctx, sink, now)
}

func (s *AutorunsLiteSource) emitRegistryValues(ctx context.Context, sink *StreamingSink, root registry.Key, subpath, technique string, ts time.Time) {
	k, err := registry.OpenKey(root, subpath, registry.READ)
	if err != nil {
		return
	}
	defer k.Close()
	names, err := k.ReadValueNames(-1)
	if err != nil {
		return
	}
	for _, name := range names {
		val, _, err := k.GetStringValue(name)
		if err != nil {
			continue
		}
		s.emitPersistence(ctx, sink, technique, subpath+"\\"+name, val, ts)
	}
}

func (s *AutorunsLiteSource) emitIFEO(ctx context.Context, sink *StreamingSink, ts time.Time) {
	const p = `SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options`
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, p, registry.READ)
	if err != nil {
		return
	}
	defer k.Close()
	subs, err := k.ReadSubKeyNames(-1)
	if err != nil {
		return
	}
	for _, exe := range subs {
		sk, err := registry.OpenKey(k, exe, registry.READ)
		if err != nil {
			continue
		}
		dbg, _, _ := sk.GetStringValue("Debugger")
		_ = sk.Close()
		if strings.TrimSpace(dbg) == "" {
			continue
		}
		s.emitPersistence(ctx, sink, "ifeo_debugger", p+`\`+exe, dbg, ts)
	}
}

func (s *AutorunsLiteSource) emitSchtasks(ctx context.Context, sink *StreamingSink, ts time.Time) {
	if _, err := exec.LookPath("schtasks"); err != nil {
		return
	}
	cmd := exec.CommandContext(ctx, "schtasks", "/Query", "/FO", "CSV", "/NH")
	out, err := cmd.Output()
	if err != nil || len(out) == 0 {
		return
	}
	for _, line := range bytes.Split(out, []byte{'\n'}) {
		if len(line) == 0 {
			continue
		}
		fields := strings.Split(string(line), ",")
		if len(fields) < 2 {
			continue
		}
		name := strings.Trim(fields[0], `"`)
		if name == "" {
			continue
		}
		s.emitPersistence(ctx, sink, "scheduled_task", "schtasks", name, ts)
	}
}

func (s *AutorunsLiteSource) emitPersistence(ctx context.Context, sink *StreamingSink, technique, itemType, path string, ts time.Time) {
	s.eventsTotal.Add(1)
	pe := &schema.ProcessEvent{
		BaseEvent: schema.BaseEvent{
			SchemaVersion: schema.SchemaVersionV1,
			EventType:     schema.EventProcess,
			EndpointID:    s.endpointID,
			Timestamp:     ts,
			Hostname:      s.hostname,
			OS:            runtime.GOOS,
		},
		ProcessName: "windows_autorun",
		ProcessPath: itemType,
		CommandLine: technique + "=" + path,
		Tags:        []string{"persistence", "windows-autorun"},
	}
	if sink != nil {
		_ = sink.Send(ctx, Telemetry{Process: pe})
	}
}
