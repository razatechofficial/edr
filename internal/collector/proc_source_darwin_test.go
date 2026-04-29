//go:build darwin

package collector

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"
)

func TestDarwinProcSource_FirstSnapshotEmitsThenStable(t *testing.T) {
	tr := NewLineageTracker(64, time.Hour)
	s := NewDarwinProcSource("ep", "host", tr)
	first, err := s.Snapshot(context.Background())
	if err != nil {
		if isDarwinProcPermissionDenied(err) {
			t.Skip("sysctl kern.proc.all not permitted in this environment")
		}
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
		if isDarwinProcPermissionDenied(err) {
			t.Skip("sysctl kern.proc.all not permitted in this environment")
		}
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
	_, err := s.Snapshot(context.Background())
	if err != nil && isDarwinProcPermissionDenied(err) {
		t.Skip("sysctl not permitted")
	}
	h := s.ExportMonitoringHealth()
	if h["source"] != "sysctl" {
		t.Fatalf("source=%v", h["source"])
	}
}

func isDarwinProcPermissionDenied(err error) bool {
	if err == nil {
		return false
	}
	s := strings.ToLower(err.Error())
	return strings.Contains(s, "not permitted") || strings.Contains(s, "permission denied")
}
