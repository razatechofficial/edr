//go:build darwin

package collector

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
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

// MacosNotarizationPostureSource reports XProtect/MRT/Gatekeeper/SIP snapshots (cheap read-only probes).
type MacosNotarizationPostureSource struct {
	endpointID string
	hostname   string
	cfg        config.Config

	emits atomic.Uint64
	last  atomic.Int64
}

func NewMacosNotarizationPostureSource(endpointID string, cfg config.Config) *MacosNotarizationPostureSource {
	h, _ := os.Hostname()
	return &MacosNotarizationPostureSource{endpointID: endpointID, hostname: h, cfg: cfg}
}

func (s *MacosNotarizationPostureSource) ExportMonitoringHealth() map[string]any {
	m := MonitoringSource{
		Name:          "macos_notarization_posture",
		OS:            runtime.GOOS,
		Source:        "baseline",
		Status:        "healthy",
		EPSOut:        s.emits.Load(),
		LastEventUnix: s.last.Load(),
	}.ToMap()
	m["enabled"] = s.cfg.Monitoring.MacosNotarizationPosture
	return m
}

func (s *MacosNotarizationPostureSource) Run(ctx context.Context, sink *StreamingSink) error {
	if !s.cfg.Monitoring.MacosNotarizationPosture {
		return nil
	}
	iv := s.cfg.Monitoring.MacosNotarizationIntervalSec
	if iv <= 0 {
		iv = 3600
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

func (s *MacosNotarizationPostureSource) scan(ctx context.Context, sink *StreamingSink) {
	now := time.Now().UTC()
	s.last.Store(now.Unix())

	if st, digest, ok := artifactDigest("/Library/Apple/System/Library/CoreServices/XProtect.bundle/Contents/Resources/XProtect.meta.plist"); ok {
		s.emit(ctx, sink, now, "posture.xprotect_state", "plist meta sha256="+digest+" mtime="+st.ModTime().UTC().Format(time.RFC3339))
	}
	if st, digest, ok := artifactDigest("/Library/Apple/System/Library/CoreServices/XProtect.bundle/Contents/Resources/XProtect.yara"); ok {
		s.emit(ctx, sink, now, "posture.xprotect_yara_state", "yara sha256="+digest+" mtime="+st.ModTime().UTC().Format(time.RFC3339))
	}
	if info := readBundleVersion("/Library/Apple/System/Library/CoreServices/MRT.app"); info != "" {
		s.emit(ctx, sink, now, "posture.mrt_version", info)
	}
	if out, err := exec.CommandContext(ctx, "spctl", "--status").CombinedOutput(); err == nil {
		t := strings.ToLower(string(out))
		if strings.Contains(t, "disabled") {
			s.emit(ctx, sink, now, "posture.gatekeeper", "gatekeeper_disabled output="+strings.TrimSpace(string(out)))
		}
	}
	if _, err := exec.LookPath("csrutil"); err == nil {
		if out, err := exec.CommandContext(ctx, "csrutil", "status").CombinedOutput(); err == nil {
			ls := strings.ToLower(string(out))
			if strings.Contains(ls, "disabled") {
				s.emit(ctx, sink, now, "posture.sip", "sip_indicator output="+strings.TrimSpace(string(out)))
			}
		}
	}
}

func readBundleVersion(bundlePath string) string {
	pl := filepath.Join(bundlePath, "Contents/Info.plist")
	if _, err := os.Stat(pl); err != nil {
		return ""
	}
	out, err := exec.Command("defaults", "read", pl, "CFBundleShortVersionString").Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

func artifactDigest(p string) (os.FileInfo, string, bool) {
	st, err := os.Stat(p)
	if err != nil {
		return nil, "", false
	}
	b, err := os.ReadFile(p)
	if err != nil {
		return nil, "", false
	}
	sum := sha256.Sum256(b)
	return st, hex.EncodeToString(sum[:]), true
}

func (s *MacosNotarizationPostureSource) emit(ctx context.Context, sink *StreamingSink, ts time.Time, verb, payload string) {
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
		ProcessName: "posture",
		ProcessPath: "macos_baseline",
		CommandLine: verb + " " + payload,
		Tags:        []string{"posture", "macos-baseline"},
		Severity:    "low",
	}
	if sink != nil {
		_ = sink.Send(ctx, Telemetry{Process: pe})
	}
}
