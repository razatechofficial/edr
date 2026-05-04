package collector

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/razatechofficial/edr/internal/config"
)

func TestLogTailFileEventsPerLineAndOffsets(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "app.log")
	if err := os.WriteFile(logPath, []byte("alpha\nbeta\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	var cfg config.Config
	cfg.Service.EndpointID = "ep-test"
	cfg.Agent.DataDir = dir
	cfg.Monitoring.AdditionalLogTailPaths = []string{logPath}
	cfg.Monitoring.LogTailTelemetryMode = "file_events"
	cfg.Monitoring.StreamMaxEPS = 100
	lt := NewLogTailCollector(cfg)
	if lt == nil {
		t.Fatal("expected LogTailCollector")
	}
	out, err := lt.Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != 2 {
		t.Fatalf("events=%d want 2", len(out))
	}
	for i, want := range []string{"alpha", "beta"} {
		if out[i].File == nil {
			t.Fatalf("event %d: want File", i)
		}
		if out[i].File.Operation != "log_tail_line" {
			t.Fatalf("op=%q", out[i].File.Operation)
		}
		if out[i].File.BytesWritten != uint64(len(want)) {
			t.Fatalf("bytes=%d want %d", out[i].File.BytesWritten, len(want))
		}
	}
	// Second collect: same file, no new bytes → no new events
	out2, err := lt.Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(out2) != 0 {
		t.Fatalf("second collect events=%d want 0", len(out2))
	}
	if err := os.WriteFile(logPath, []byte("alpha\nbeta\ngamma\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	out3, err := lt.Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(out3) != 1 || out3[0].File == nil {
		t.Fatalf("third events=%d", len(out3))
	}
	if out3[0].File.BytesWritten != 5 { // "gamma"
		t.Fatalf("gamma bytes=%d", out3[0].File.BytesWritten)
	}
}

func TestLogTailOffsetsPersistAcrossRestarts(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "persist.log")
	if err := os.WriteFile(logPath, []byte("one\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	var cfg config.Config
	cfg.Service.EndpointID = "ep-persist"
	cfg.Agent.DataDir = dir
	cfg.Monitoring.AdditionalLogTailPaths = []string{logPath}
	cfg.Monitoring.LogTailTelemetryMode = "file_events"
	cfg.Monitoring.StreamMaxEPS = 50

	lt1 := NewLogTailCollector(cfg)
	out1, err := lt1.Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(out1) != 1 {
		t.Fatalf("first collect events=%d want 1", len(out1))
	}

	lt2 := NewLogTailCollector(cfg)
	out2, err := lt2.Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(out2) != 0 {
		t.Fatalf("after reload with no new bytes events=%d want 0", len(out2))
	}

	if err := os.WriteFile(logPath, []byte("one\ntwo\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	lt3 := NewLogTailCollector(cfg)
	out3, err := lt3.Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(out3) != 1 {
		t.Fatalf("after append events=%d want 1", len(out3))
	}
}

func TestLogTailFileEventsRateLimitDrops(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "burst.log")
	var b strings.Builder
	for i := 0; i < 20; i++ {
		b.WriteString("x\n")
	}
	if err := os.WriteFile(logPath, []byte(b.String()), 0o644); err != nil {
		t.Fatal(err)
	}
	var cfg config.Config
	cfg.Service.EndpointID = "ep-test"
	cfg.Agent.DataDir = dir
	cfg.Monitoring.AdditionalLogTailPaths = []string{logPath}
	cfg.Monitoring.LogTailTelemetryMode = "file_events"
	cfg.Monitoring.StreamMaxEPS = 5
	lt := NewLogTailCollector(cfg)
	out, err := lt.Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(out) > 5 {
		t.Fatalf("emitted=%d want <=5", len(out))
	}
	if lt.dropped.Load() == 0 {
		t.Fatal("expected some drops when stream_max_eps caps")
	}
}
