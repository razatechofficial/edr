//go:build darwin

package collector

import (
	"context"
	"os"
	"testing"
	"time"
)

func TestDarwinProcSource_FirstSnapshotEmitsThenStable(t *testing.T) {
	tr := NewLineageTracker(64, time.Hour)
	s := NewDarwinProcSource("ep", "host", tr)
	first, err := s.Snapshot(context.Background())
	if err != nil {
		t.Fatalf("first: %v", err)
	}
	if len(first) == 0 {
		t.Fatal("expected at least one process on first snapshot")
	}
	second, err := s.Snapshot(context.Background())
	if err != nil {
		t.Fatalf("second: %v", err)
	}
	if len(second) >= len(first) {
		t.Fatalf("expected fewer emits on second; first=%d second=%d", len(first), len(second))
	}
}

func TestDarwinProcSource_SelfPIDPresent(t *testing.T) {
	s := NewDarwinProcSource("ep", "host", NewLineageTracker(64, time.Hour))
	telems, err := s.Snapshot(context.Background())
	if err != nil {
		t.Fatalf("snapshot: %v", err)
	}
	mypid := os.Getpid()
	for _, te := range telems {
		if te.Process != nil && te.Process.PID == mypid {
			return
		}
	}
	t.Fatalf("self pid=%d not found", mypid)
}

func TestDarwinProcSourceHealth(t *testing.T) {
	s := NewDarwinProcSource("ep", "host", nil)
	_, _ = s.Snapshot(context.Background())
	h := s.ExportMonitoringHealth()
	if h["source"] != "sysctl" {
		t.Fatalf("source=%v", h["source"])
	}
}
