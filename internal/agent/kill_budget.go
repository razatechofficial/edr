package agent

import (
	"sync"
	"time"
)

// killBudget bounds how many processes automated response may terminate in a
// rolling window.
//
// Without it, one rule that matches broadly terminates processes for as long as
// it keeps matching. That is not a hypothetical: the shipped default allowed
// every rule to kill, and a single run recorded hundreds of terminations
// against shells, editors and system daemons. A budget converts that failure
// mode from an outage into a bounded incident with an alert attached.
//
// The window slides rather than resetting on the hour, so an attacker cannot
// wait for a boundary to get a fresh allocation.
type killBudget struct {
	mu     sync.Mutex
	limit  int
	window time.Duration
	events []time.Time
	now    func() time.Time
}

func newKillBudget(limit int) *killBudget {
	if limit <= 0 {
		// A non-positive limit means no automated termination at all, not
		// unlimited. Read the other way round, a misconfigured zero would be
		// the most permissive setting available.
		limit = 0
	}
	return &killBudget{limit: limit, window: time.Hour, now: time.Now}
}

// allow reports whether one more termination fits, and records it if so.
func (b *killBudget) allow() bool {
	if b == nil {
		return false
	}
	b.mu.Lock()
	defer b.mu.Unlock()

	cutoff := b.now().Add(-b.window)
	kept := b.events[:0]
	for _, t := range b.events {
		if t.After(cutoff) {
			kept = append(kept, t)
		}
	}
	b.events = kept

	if len(b.events) >= b.limit {
		return false
	}
	b.events = append(b.events, b.now())
	return true
}

// used reports how much of the budget the current window has consumed, for the
// log line that explains a refusal.
func (b *killBudget) used() (int, int) {
	if b == nil {
		return 0, 0
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	cutoff := b.now().Add(-b.window)
	n := 0
	for _, t := range b.events {
		if t.After(cutoff) {
			n++
		}
	}
	return n, b.limit
}
