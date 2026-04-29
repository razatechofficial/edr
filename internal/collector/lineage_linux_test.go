//go:build linux

package collector

import (
	"os"
	"testing"
	"time"
)

func TestEnrichFromProcLinux_PopulatesCgroup(t *testing.T) {
	tr := NewLineageTracker(8, time.Hour)
	tr.EnrichFromProcLinux(uint32(os.Getpid()))
	entry, ok := tr.Get(uint32(os.Getpid()))
	if !ok {
		t.Fatal("expected lineage entry for self pid")
	}
	if entry.Cgroup == "" {
		t.Fatal("expected non-empty Cgroup for self process")
	}
}

func TestEnrichFromProcLinux_NoOpOnZeroPID(t *testing.T) {
	tr := NewLineageTracker(8, time.Hour)
	tr.EnrichFromProcLinux(0)
	if size, _, _, _, _ := tr.Stats(); size != 0 {
		t.Fatalf("expected empty tracker, size=%d", size)
	}
}
