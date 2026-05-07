//go:build windows

package collector

import (
	"context"
	"encoding/hex"
	"os"
	"runtime"
	"strings"
	"sync/atomic"
	"time"

	"github.com/razatechofficial/edr/internal/config"
	"github.com/razatechofficial/edr/internal/schema"
	"golang.org/x/sys/windows"
)

// AmsiEtwTamperSource performs periodic user-mode prologue probes for AMSI / ETW exports.
type AmsiEtwTamperSource struct {
	endpointID string
	hostname   string
	cfg        config.Config

	eventsTotal atomic.Uint64
	lastUnix    atomic.Int64
	lastErr     atomic.Value // string

	amsiOK atomic.Bool
	etwOK  atomic.Bool
}

func NewAmsiEtwTamperSource(endpointID, hostname string, cfg config.Config) *AmsiEtwTamperSource {
	if hostname == "" {
		hostname, _ = os.Hostname()
	}
	return &AmsiEtwTamperSource{endpointID: endpointID, hostname: hostname, cfg: cfg}
}

func (s *AmsiEtwTamperSource) ExportMonitoringHealth() map[string]any {
	src := MonitoringSource{
		Name:          "amsi_etw_tamper",
		OS:            runtime.GOOS,
		Source:        "user_probe",
		Status:        "healthy",
		EPSOut:        s.eventsTotal.Load(),
		LastEventUnix: s.lastUnix.Load(),
	}.ToMap()
	src["enabled"] = s.cfg.Monitoring.WindowsAmsiTamperEnabled || s.cfg.Monitoring.WindowsEtwTamperEnabled
	src["amsi_prologue_matches_known"] = s.amsiOK.Load()
	src["etw_prologue_matches_known"] = s.etwOK.Load()
	if v, _ := s.lastErr.Load().(string); v != "" {
		src["last_error"] = v
	}
	return src
}

func (s *AmsiEtwTamperSource) Run(ctx context.Context, sink *StreamingSink) error {
	if !s.cfg.Monitoring.WindowsAmsiTamperEnabled && !s.cfg.Monitoring.WindowsEtwTamperEnabled {
		return nil
	}
	iv := s.cfg.Monitoring.WindowsTamperIntervalSec
	if iv <= 0 {
		iv = 60
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

func (s *AmsiEtwTamperSource) probe(ctx context.Context, sink *StreamingSink) {
	s.lastErr.Store("")
	now := time.Now().UTC()
	s.lastUnix.Store(now.Unix())

	var amsiSusp, etwSusp bool
	if s.cfg.Monitoring.WindowsAmsiTamperEnabled {
		amsiSusp = s.probeExport("amsi.dll", "AmsiScanBuffer", "amsi_tamper")
		s.amsiOK.Store(!amsiSusp)
	}
	if s.cfg.Monitoring.WindowsEtwTamperEnabled {
		etwSusp = s.probeExport("ntdll.dll", "EtwEventWrite", "etw_tamper")
		s.etwOK.Store(!etwSusp)
	}

	if amsiSusp || etwSusp {
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
			PID:         os.Getpid(),
			ProcessName: "posture",
			ProcessPath: "amsi_etw_tamper",
			CommandLine: strings.TrimSpace(strings.Join([]string{
				func() string {
					if amsiSusp {
						return "posture.amsi_tamper=1"
					}
					return ""
				}(),
				func() string {
					if etwSusp {
						return "posture.etw_tamper=1"
					}
					return ""
				}(),
			}, " ")),
			Tags:     []string{"posture", "windows-tamper"},
			Severity: "medium",
		}
		if sink != nil {
			_ = sink.Send(ctx, Telemetry{Process: pe})
		}
	}
}

func (s *AmsiEtwTamperSource) probeExport(dllName, export, tag string) (suspicious bool) {
	dll := windows.NewLazyDLL(dllName)
	if err := dll.Load(); err != nil {
		s.lastErr.Store(err.Error())
		return false
	}
	p := dll.NewProc(export)
	addr := p.Addr()
	if addr == 0 {
		s.lastErr.Store("export_addr_zero:" + dllName + "!" + export)
		return false
	}
	var buf [16]byte
	var n uintptr
	err := windows.ReadProcessMemory(windows.CurrentProcess(), addr, &buf[0], uintptr(len(buf)), &n)
	if err != nil {
		s.lastErr.Store(err.Error())
		return false
	}
	if prologueSuspicious(buf[:int(n)]) {
		s.lastErr.Store(tag + ":unexpected_prologue=" + hex.EncodeToString(buf[:int(n)]))
		return true
	}
	return false
}

func prologueSuspicious(b []byte) bool {
	if len(b) < 2 {
		return true
	}
	switch b[0] {
	case 0xe9, 0xeb, 0xc3, 0xcc:
		return true
	}
	return false
}
