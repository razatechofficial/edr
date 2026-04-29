//go:build linux

package collector

import (
	"context"
	"strings"
	"testing"
	"time"
)

func TestSocketSource_HealthSnapshotShape(t *testing.T) {
	s := NewSocketSource("ep", "host", NewLineageTracker(8, time.Hour))
	if _, err := s.Snapshot(context.Background()); err != nil {
		t.Fatalf("snapshot: %v", err)
	}
	h := s.ExportMonitoringHealth()
	if h["source"] != "proc-sock" || h["name"] != "network" {
		t.Fatalf("unexpected health: %v", h)
	}
}

func TestParseProcNetAddr_V4Loopback(t *testing.T) {
	ip, port, ok := parseProcNetAddr("0100007F:1F90", false) // 127.0.0.1:8080
	if !ok || ip != "127.0.0.1" || port != 8080 {
		t.Fatalf("got ip=%q port=%d ok=%v", ip, port, ok)
	}
}

func TestParseProcNetAddr_V6Loopback(t *testing.T) {
	ip, port, ok := parseProcNetAddr("00000000000000000000000001000000:0050", true) // ::1:80
	if !ok || port != 80 {
		t.Fatalf("got ip=%q port=%d ok=%v", ip, port, ok)
	}
	if !strings.Contains(ip, "::") {
		t.Errorf("expected v6 form, got %q", ip)
	}
}

func TestSocketSource_DedupSuppressesRepeatSnapshots(t *testing.T) {
	s := NewSocketSource("ep", "host", NewLineageTracker(64, time.Hour))
	first, _ := s.Snapshot(context.Background())
	second, _ := s.Snapshot(context.Background())
	if len(second) > len(first) {
		t.Fatalf("expected second snapshot <= first; first=%d second=%d", len(first), len(second))
	}
}
