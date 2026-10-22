package agent

import (
	"testing"
	"time"
)

func TestBudgetAllowsUpToTheLimitThenRefuses(t *testing.T) {
	b := newKillBudget(3)
	for i := 0; i < 3; i++ {
		if !b.allow() {
			t.Fatalf("termination %d was refused inside the limit", i+1)
		}
	}
	if b.allow() {
		t.Fatal("a fourth termination was allowed past a limit of 3")
	}
	used, limit := b.used()
	if used != 3 || limit != 3 {
		t.Errorf("used/limit = %d/%d, want 3/3", used, limit)
	}
}

// The window slides rather than resetting on the hour, so waiting for a
// boundary does not hand out a fresh allocation.
func TestBudgetWindowSlides(t *testing.T) {
	now := time.Now()
	b := newKillBudget(2)
	b.now = func() time.Time { return now }

	if !b.allow() || !b.allow() {
		t.Fatal("the first two terminations should fit")
	}
	if b.allow() {
		t.Fatal("a third was allowed inside the window")
	}

	// Half an hour on, the first two are still inside a one hour window.
	now = now.Add(30 * time.Minute)
	if b.allow() {
		t.Fatal("the window reset early")
	}

	// Past the hour, the earlier terminations have aged out.
	now = now.Add(31 * time.Minute)
	if !b.allow() {
		t.Fatal("the window did not slide")
	}
}

// A zero or negative limit must mean no automated termination, not unlimited.
// Read the other way round, a misconfigured 0 would be the most permissive
// setting available.
func TestZeroLimitRefusesEverything(t *testing.T) {
	for _, limit := range []int{0, -1} {
		b := newKillBudget(limit)
		if b.allow() {
			t.Errorf("limit %d allowed a termination", limit)
		}
	}
}

// A nil budget must refuse rather than panic: an agent built without one is
// misconfigured, and the safe reading of misconfigured is "do not kill".
func TestNilBudgetRefuses(t *testing.T) {
	var b *killBudget
	if b.allow() {
		t.Fatal("a nil budget allowed a termination")
	}
}
