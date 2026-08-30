//go:build windows

package collector

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"sync/atomic"
	"time"

	"github.com/razatechofficial/edr/internal/config"
	"github.com/razatechofficial/edr/internal/schema"
)

// WMIPersistenceWatchSource dumps root\subscription MOF classes (best-effort).
type WMIPersistenceWatchSource struct {
	endpointID string
	hostname   string
	cfg        config.Config

	emits   atomic.Uint64
	lastRun atomic.Int64
	skips   atomic.Uint64
}

func NewWMIPersistenceWatchSource(endpointID string, cfg config.Config) *WMIPersistenceWatchSource {
	h, _ := os.Hostname()
	return &WMIPersistenceWatchSource{endpointID: endpointID, hostname: h, cfg: cfg}
}

func (s *WMIPersistenceWatchSource) ExportMonitoringHealth() map[string]any {
	m := MonitoringSource{
		Name:          "wmi_persistence",
		OS:            runtime.GOOS,
		Source:        "wmi",
		Status:        "healthy",
		EPSOut:        s.emits.Load(),
		LastEventUnix: s.lastRun.Load(),
	}.ToMap()
	m["enabled"] = s.cfg.Monitoring.WindowsWMIPersistenceHunt
	m["wmi_skipped_total"] = s.skips.Load()
	return m
}

func (s *WMIPersistenceWatchSource) Run(ctx context.Context, sink *StreamingSink) error {
	if !s.cfg.Monitoring.WindowsWMIPersistenceHunt {
		return nil
	}
	iv := s.cfg.Monitoring.WindowsWMIIntervalSec
	if iv <= 0 {
		iv = 3600
	}
	t := time.NewTicker(time.Duration(iv) * time.Second)
	defer t.Stop()
	s.dump(ctx, sink)
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
			s.dump(ctx, sink)
		}
	}
}

func (s *WMIPersistenceWatchSource) dump(ctx context.Context, sink *StreamingSink) {
	now := time.Now().UTC()
	s.lastRun.Store(now.Unix())

	psPath := `powershell.exe`
	if _, err := exec.LookPath(psPath); err != nil {
		psPath = `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`
	}
	var out strings.Builder
	for _, cn := range []string{"__EventConsumer", "__EventFilter", "__FilterToConsumerBinding"} {
		script := fmt.Sprintf(
			"$e=Get-CimInstance -Namespace root/subscription -ClassName %s -ErrorAction SilentlyContinue; if($null -ne $e){$e|ConvertTo-Csv -NoTypeInformation}", cn)
		cmd := exec.CommandContext(ctx, psPath, "-NoProfile", "-STA", "-Command", script)
		hideConsole(cmd)
		b, err := cmd.CombinedOutput()
		if err != nil || len(b) == 0 {
			continue
		}
		out.WriteString(string(b))
		out.WriteByte('\n')
	}

	data := strings.TrimSpace(out.String())
	if data == "" {
		s.skips.Add(1)
		return
	}
	for _, line := range strings.Split(data, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if ctx.Err() != nil {
			return
		}
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
			ProcessName: "windows_wmi_subscription",
			ProcessPath: "root/subscription",
			CommandLine: line,
			Tags:        []string{"persistence", "wmi-eventsubscription"},
		}
		if sink != nil {
			_ = sink.Send(ctx, Telemetry{Process: pe})
		}
	}
}
