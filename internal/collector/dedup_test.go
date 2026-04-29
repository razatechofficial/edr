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

func TestEventDeduper_GenericKey(t *testing.T) {
	d := NewEventDeduper(64, time.Second)
	if !d.ShouldEmit("k1", 100*time.Millisecond) {
		t.Fatal("first emit should pass")
	}
	if d.ShouldEmit("k1", 100*time.Millisecond) {
		t.Fatal("repeat in window should suppress")
	}
	if !d.ShouldEmit("k2", 100*time.Millisecond) {
		t.Fatal("different key should pass")
	}
	time.Sleep(120 * time.Millisecond)
	if !d.ShouldEmit("k1", 100*time.Millisecond) {
		t.Fatal("emit should pass after window")
	}
}

func TestEventDeduper_BoundedMemory(t *testing.T) {
	d := NewEventDeduper(32, time.Hour)
	for i := 0; i < 1000; i++ {
		d.ShouldEmit(fmtKey(i), time.Second)
	}
	size, _, _ := d.Stats()
	if size > 32 {
		t.Fatalf("dedup map exceeded cap: size=%d", size)
	}
}

func fmtKey(i int) string {
	return "k" + time.Now().Format("150405") + "-" + intToStr(i)
}

func intToStr(i int) string {
	if i == 0 {
		return "0"
	}
	var buf [20]byte
	pos := len(buf)
	negative := i < 0
	if negative {
		i = -i
	}
	for i > 0 {
		pos--
		buf[pos] = byte('0' + i%10)
		i /= 10
	}
	if negative {
		pos--
		buf[pos] = '-'
	}
	return string(buf[pos:])
}
