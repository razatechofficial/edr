//go:build darwin

package main

import (
	"testing"
	"time"
)

func TestReadCPUTicksDarwin(t *testing.T) {
	idle, total := readCPUTicks()
	if total == 0 || idle > total {
		t.Fatalf("idle=%d total=%d", idle, total)
	}
	time.Sleep(50 * time.Millisecond)
	idle2, total2 := readCPUTicks()
	if total2 <= total {
		t.Fatalf("ticks did not advance %d → %d", total, total2)
	}
	if idle2 < idle {
		t.Fatalf("idle went backwards %d → %d", idle, idle2)
	}
	pct := busyCPU(idle, total, idle2, total2)
	if pct < 0 || pct > 100 {
		t.Fatalf("busy %v", pct)
	}
}
