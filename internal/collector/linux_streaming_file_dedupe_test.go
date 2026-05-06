package collector

import (
	"testing"
	"time"
)

func TestLinuxFileDeduper_AllowAndSkipped(t *testing.T) {
	t.Parallel()
	d := NewLinuxFileDeduper(500 * time.Millisecond)
	if d == nil {
		t.Fatal("expected deduper")
	}
	if !d.Allow("/tmp/a") {
		t.Fatal("first allow")
	}
	if d.Allow("/tmp/a") {
		t.Fatal("expected duplicate within window")
	}
	if d.Skipped() != 1 {
		t.Fatalf("skipped %d", d.Skipped())
	}
	sm := d.StatsMap()
	if sm["skipped_total"].(uint64) != 1 {
		t.Fatalf("stats skipped_total: %v", sm["skipped_total"])
	}
}
