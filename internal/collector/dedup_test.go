package collector

import (
	"testing"
	"time"

	"github.com/razatechofficial/edr/internal/schema"
)

func TestFileDeduper(t *testing.T) {
	d := NewFileDeduper(500 * time.Millisecond)
	if !d.ShouldEmitFile(schema.EventFile, 1, "/tmp/a", "write") {
		t.Fatal("first emit")
	}
	if d.ShouldEmitFile(schema.EventFile, 1, "/tmp/a", "write") {
		t.Fatal("expected suppress")
	}
	if !d.ShouldEmitFile(schema.EventFile, 1, "/tmp/a", "delete") {
		t.Fatal("different operation should emit")
	}
}

func TestFileDeduper_ProcessCycleSemantics(t *testing.T) {
	d := NewFileDeduper(500 * time.Millisecond)
	passes := 0
	for i := 0; i < 3; i++ {
		if d.ShouldEmitFile(schema.EventFile, 42, "/same/path", "write") {
			passes++
		}
	}
	if passes != 1 {
		t.Fatalf("expected exactly 1 pass in window, got %d", passes)
	}
	time.Sleep(501 * time.Millisecond)
	if !d.ShouldEmitFile(schema.EventFile, 42, "/same/path", "write") {
		t.Fatal("expected pass after window")
	}
}
