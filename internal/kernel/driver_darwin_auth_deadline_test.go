//go:build darwin && cgo && !nosec

package kernel

import (
	"testing"
	"time"
)

func TestAuthWait_UsesMinOfBudgetAndDefault(t *testing.T) {
	t.Parallel()
	auth := 750 * time.Millisecond
	budget := 100
	wait := auth
	bd := time.Duration(budget) * time.Millisecond
	if budget == 0 {
		wait = 5 * time.Millisecond
	} else if bd < wait {
		wait = bd
	}
	if wait != 100*time.Millisecond {
		t.Fatalf("wait=%v", wait)
	}
}

func TestObserveAuthBudgetRingAndP50(t *testing.T) {
	t.Parallel()
	d := &ESFDriver{}
	for i := 0; i < 1300; i++ {
		d.observeAuthBudgetMs(i)
	}
	if got := len(d.authSamples); got != 1024 {
		t.Fatalf("ring size=%d want 1024", got)
	}
	h := d.AuthHealth()
	p50, ok := h["auth_deadline_p50_ms"].(int)
	if !ok {
		t.Fatalf("missing p50 in health: %#v", h)
	}
	// After 1300 inserts with cap 1024, retained sorted range is [276..1299], median idx 512 -> 788.
	if p50 != 788 {
		t.Fatalf("p50=%d want 788", p50)
	}
}
