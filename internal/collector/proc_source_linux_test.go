//go:build linux

package collector

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"
)

func TestProcSource_EmitsOnlyForNewPIDs(t *testing.T) {
	tracker := NewLineageTracker(64, time.Hour)
	src := NewProcSource("ep", "host", tracker)

	first, err := src.Snapshot(context.Background())
	if err != nil {
		t.Fatalf("first snapshot: %v", err)
	}
	if len(first) == 0 {
		t.Fatal("expected at least one process on first snapshot")
	}

	second, err := src.Snapshot(context.Background())
	if err != nil {
		t.Fatalf("second snapshot: %v", err)
	}
	if len(second) >= len(first) {
		t.Fatalf("second snapshot emitted %d events, want < %d (no churn since first)", len(second), len(first))
	}
}

func TestProcSource_IncludesCurrentProcessOnFirstScan(t *testing.T) {
	tracker := NewLineageTracker(64, time.Hour)
	src := NewProcSource("ep", "host", tracker)
	telems, err := src.Snapshot(context.Background())
	if err != nil {
		t.Fatalf("snapshot: %v", err)
	}
	mypid := os.Getpid()
	for _, te := range telems {
		if te.Process != nil && te.Process.PID == mypid {
			if te.Process.PPID == 0 {
				t.Errorf("expected non-zero PPID for self pid=%d", mypid)
			}
			return
		}
	}
	t.Fatalf("self pid=%d not found in first snapshot", mypid)
}

func TestProcSource_ForgetsExitedPIDs(t *testing.T) {
	tracker := NewLineageTracker(64, time.Hour)
	src := NewProcSource("ep", "host", tracker)
	if _, err := src.Snapshot(context.Background()); err != nil {
		t.Fatalf("snapshot: %v", err)
	}
	src.mu.Lock()
	src.known[999_999] = 12345 // synthetic ghost pid
	src.mu.Unlock()
	if _, err := src.Snapshot(context.Background()); err != nil {
		t.Fatalf("second snapshot: %v", err)
	}
	src.mu.Lock()
	_, present := src.known[999_999]
	src.mu.Unlock()
	if present {
		t.Fatal("expected ghost pid to be reaped on next snapshot")
	}
}

func TestProcSourceHealthSnapshot(t *testing.T) {
	src := NewProcSource("ep", "host", NewLineageTracker(8, time.Hour))
	if _, err := src.Snapshot(context.Background()); err != nil {
		t.Fatalf("snapshot: %v", err)
	}
	h := src.ExportMonitoringHealth()
	if h["source"] != "proc" || h["name"] != "process" {
		t.Fatalf("health snapshot misformed: %v", h)
	}
	if status, _ := h["status"].(string); !strings.HasPrefix(status, "health") && status != "degraded" {
		t.Fatalf("status=%q", status)
	}
}
