//go:build windows

package collector

import (
	"context"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/razatechofficial/edr/internal/config"
	"github.com/razatechofficial/edr/internal/schema"
	"golang.org/x/sys/windows/registry"
)

// DLLSearchPostureSource emits events when DLL search hardening reg keys are weakened.
type DLLSearchPostureSource struct {
	endpointID string
	hostname   string
	cfg        config.Config

	emits   atomic.Uint64
	lastRun atomic.Int64
}

func NewDLLSearchPostureSource(endpointID string, cfg config.Config) *DLLSearchPostureSource {
	h, _ := os.Hostname()
	return &DLLSearchPostureSource{endpointID: endpointID, hostname: h, cfg: cfg}
}

func (s *DLLSearchPostureSource) ExportMonitoringHealth() map[string]any {
	m := MonitoringSource{
		Name:          "dll_search_posture",
		OS:            runtime.GOOS,
		Source:        "registry",
		Status:        "healthy",
		EPSOut:        s.emits.Load(),
		LastEventUnix: s.lastRun.Load(),
	}.ToMap()
	m["enabled"] = s.cfg.Monitoring.WindowsDLLSearchPosture
	return m
}

func (s *DLLSearchPostureSource) Run(ctx context.Context, sink *StreamingSink) error {
	if !s.cfg.Monitoring.WindowsDLLSearchPosture {
		return nil
	}
	iv := s.cfg.Monitoring.WindowsAutorunsIntervalSec
	if iv <= 0 {
		iv = 300
	}
	t := time.NewTicker(time.Duration(iv) * time.Second)
	defer t.Stop()
	s.probe(ctx, sink)
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
			s.probe(ctx, sink)
		}
	}
}

func (s *DLLSearchPostureSource) probe(ctx context.Context, sink *StreamingSink) {
	now := time.Now().UTC()
	s.lastRun.Store(now.Unix())
	const sess = `SYSTEM\CurrentControlSet\Control\Session Manager`
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, sess, registry.READ)
	if err != nil {
		return
	}
	defer k.Close()

	if v, _, err := k.GetIntegerValue("SafeDllSearchMode"); err != nil || v != 1 {
		s.emit(ctx, sink, now, sess+`\SafeDllSearchMode`, "expected_dword_1_actual="+u64String(v, err))
	}
	if v, _, err := k.GetIntegerValue("CWDIllegalInDllSearch"); err != nil || v == 0 {
		s.emit(ctx, sink, now, sess+`\CWDIllegalInDllSearch`, "expected_nonzero_actual="+u64String(v, err))
	}

	if altPath, _, e := k.GetStringValue("AlternateShell"); e == nil {
		al := strings.TrimSpace(strings.ToLower(os.ExpandEnv(altPath)))
		if al != "" && !strings.HasSuffix(al, `cmd.exe`) && !strings.HasSuffix(al, `cmd`) {
			s.emit(ctx, sink, now, sess+`\AlternateShell`, "unexpected="+altPath)
		}
	}
}

func u64String(v uint64, err error) string {
	if err != nil {
		return "missing"
	}
	return strconv.FormatUint(v, 10)
}

func (s *DLLSearchPostureSource) emit(ctx context.Context, sink *StreamingSink, ts time.Time, path, detail string) {
	s.emits.Add(1)
	pe := &schema.ProcessEvent{
		BaseEvent: schema.BaseEvent{
			SchemaVersion: schema.SchemaVersionV1,
			EventType:     schema.EventProcess,
			EndpointID:    s.endpointID,
			Timestamp:     ts,
			Hostname:      s.hostname,
			OS:            runtime.GOOS,
		},
		ProcessName: "posture.dll_search",
		ProcessPath: path,
		CommandLine: "posture.dll_search_hard " + detail,
		Tags:        []string{"posture", "dll_search"},
		Severity:    "medium",
	}
	if sink != nil {
		_ = sink.Send(ctx, Telemetry{Process: pe})
	}
}
