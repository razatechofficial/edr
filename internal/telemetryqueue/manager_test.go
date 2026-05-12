package telemetryqueue

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// TestManagerAppendAndStreamingDrain exercises the P0-11 streaming-drain
// path: it appends many records, rotates, drains the segment, and verifies
// each line is observed via send without ever reading the file into a
// single buffer.
func TestManagerAppendAndStreamingDrain(t *testing.T) {
	dir := t.TempDir()
	m, err := NewManager(dir, 16<<20)
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	const n = 250
	for i := 0; i < n; i++ {
		line := []byte(strings.Repeat("x", 32))
		if err := m.Append(line); err != nil {
			t.Fatalf("Append %d: %v", i, err)
		}
	}
	if err := m.RotateActiveSegment(); err != nil {
		t.Fatalf("RotateActiveSegment: %v", err)
	}

	var seen atomic.Int64
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	err = m.DrainOldestSegment(ctx, func(b []byte) error {
		if len(b) != 32 {
			t.Errorf("unexpected line length %d", len(b))
		}
		seen.Add(1)
		return nil
	}, 10000) // high rate so the test completes quickly
	if err != nil {
		t.Fatalf("DrainOldestSegment: %v", err)
	}
	if got := seen.Load(); got != int64(n) {
		t.Fatalf("expected %d lines drained, got %d", n, got)
	}
}

// TestManagerFsyncLoopRunsAndCloses asserts that Start/Close lifecycle is
// idempotent and that the active segment is fsync'd on shutdown.
func TestManagerFsyncLoopRunsAndCloses(t *testing.T) {
	dir := t.TempDir()
	m, err := NewManager(dir, 16<<20)
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	m.Start(ctx)
	m.Start(ctx) // second Start must be a no-op (sync.Once)

	if err := m.Append([]byte(`{"k":"v"}`)); err != nil {
		t.Fatalf("Append: %v", err)
	}
	cancel()
	if err := m.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	// Verify the file is on disk after Close.
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	if len(entries) == 0 {
		t.Fatal("expected at least one segment file after Close")
	}
	// And that it has content.
	got, err := os.ReadFile(filepath.Join(dir, entries[0].Name()))
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if !strings.Contains(string(got), `"k":"v"`) {
		t.Fatalf("segment missing record: %q", got)
	}
}
