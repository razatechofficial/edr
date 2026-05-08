//go:build windows

package collector

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"time"

	"github.com/razatechofficial/edr/internal/config"
	"github.com/razatechofficial/edr/internal/schema"
	"golang.org/x/sys/windows/registry"
)

const comHijackMaxCLSID = 450

// COMHijackWatchSource scans HKCU CLSID InprocServer shadows vs HKLM (bounded).
type COMHijackWatchSource struct {
	endpointID string
	hostname   string
	cfg        config.Config

	emits   atomic.Uint64
	lastRun atomic.Int64
}

func NewCOMHijackWatchSource(endpointID string, cfg config.Config) *COMHijackWatchSource {
	h, _ := os.Hostname()
	return &COMHijackWatchSource{endpointID: endpointID, hostname: h, cfg: cfg}
}

func (s *COMHijackWatchSource) ExportMonitoringHealth() map[string]any {
	ms := MonitoringSource{
		Name:          "com_hijack_watch",
		OS:            runtime.GOOS,
		Source:        "registry",
		Status:        "healthy",
		EPSOut:        s.emits.Load(),
		LastEventUnix: s.lastRun.Load(),
	}.ToMap()
	ms["enabled"] = s.cfg.Monitoring.WindowsCOMHijackHunt
	return ms
}

func (s *COMHijackWatchSource) Run(ctx context.Context, sink *StreamingSink) error {
	if !s.cfg.Monitoring.WindowsCOMHijackHunt {
		return nil
	}
	iv := s.cfg.Monitoring.WindowsCOMHijackIntervalSec
	if iv <= 0 {
		iv = 600
	}
	t := time.NewTicker(time.Duration(iv) * time.Second)
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

func (s *COMHijackWatchSource) scan(ctx context.Context, sink *StreamingSink) {
	now := time.Now().UTC()
	s.lastRun.Store(now.Unix())

	sysRoot := normalizeWinPath(os.Getenv("SystemRoot"))
	pf := normalizeWinPath(os.Getenv("ProgramFiles"))

	k, err := registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE\Classes\CLSID`, registry.READ)
	if err != nil {
		return
	}
	defer k.Close()
	guids, err := k.ReadSubKeyNames(-1)
	if err != nil {
		return
	}
	n := 0
	for _, g := range guids {
		if ctx.Err() != nil || n >= comHijackMaxCLSID {
			break
		}
		if len(g) < 3 {
			continue
		}
		hklmSub := `SOFTWARE\Classes\CLSID\` + g + `\InprocServer32`
		lmsk, err := registry.OpenKey(registry.LOCAL_MACHINE, hklmSub, registry.READ)
		if err != nil {
			continue
		}
		lm, _, err := lmsk.GetStringValue("")
		_ = lmsk.Close()
		if err != nil || strings.TrimSpace(lm) == "" {
			continue
		}
		hkcuSub := `Software\Classes\CLSID\` + g + `\InprocServer32`
		hkcusk, err := registry.OpenKey(registry.CURRENT_USER, hkcuSub, registry.READ)
		if err != nil {
			continue
		}
		hkcu, _, err := hkcusk.GetStringValue("")
		_ = hkcusk.Close()
		if err != nil || strings.TrimSpace(hkcu) == "" {
			continue
		}
		lmN := strings.TrimSpace(strings.ToLower(filepath.Clean(os.ExpandEnv(lm))))
		hkcN := strings.TrimSpace(strings.ToLower(filepath.Clean(os.ExpandEnv(hkcu))))
		if hkcN == lmN {
			continue
		}
		if trustedWinPath(hkcN, sysRoot, pf) && !trustedWinPath(lmN, sysRoot, pf) {
			continue
		}
		n++
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
			ProcessName: "posture.com_hijack",
			ProcessPath: g,
			CommandLine: "posture.com_hijack hklm=" + lm + " hkcu=" + hkcu,
			Tags:        []string{"posture", "com_hijack"},
			Severity:    "high",
		}
		if sink != nil {
			_ = sink.Send(ctx, Telemetry{Process: pe})
		}
	}
}
