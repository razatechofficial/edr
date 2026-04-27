package detection

import (
	"sync"
	"time"
)

type ruleBucket struct {
	tokens float64
	last   time.Time
}

// RuleRateLimiter applies a per-rule token bucket to prevent alert storms.
type RuleRateLimiter struct {
	mu          sync.Mutex
	perMinute   float64
	burst       float64
	maxEntries  int
	lastPrune   time.Time
	pruneWindow time.Duration
	buckets     map[string]ruleBucket
}

func NewRuleRateLimiter(perMinute int, burst int, maxEntries int) *RuleRateLimiter {
	if perMinute <= 0 {
		perMinute = 30
	}
	if burst <= 0 {
		burst = 10
	}
	if maxEntries <= 0 {
		maxEntries = 4096
	}
	return &RuleRateLimiter{
		perMinute:   float64(perMinute),
		burst:       float64(burst),
		maxEntries:  maxEntries,
		pruneWindow: 5 * time.Minute,
		buckets:     make(map[string]ruleBucket),
	}
}

// Allow returns true when this rule can emit an alert.
func (r *RuleRateLimiter) Allow(ruleID string) bool {
	if r == nil {
		return true
	}
	if ruleID == "" {
		ruleID = "unknown"
	}
	now := time.Now()
	r.mu.Lock()
	defer r.mu.Unlock()

	if len(r.buckets) > r.maxEntries {
		r.pruneLocked(now)
	}
	b := r.buckets[ruleID]
	if b.last.IsZero() {
		b.tokens = r.burst
		b.last = now
	}

	elapsedMin := now.Sub(b.last).Minutes()
	if elapsedMin > 0 {
		b.tokens += elapsedMin * r.perMinute
		if b.tokens > r.burst {
			b.tokens = r.burst
		}
	}
	b.last = now

	if b.tokens < 1.0 {
		r.buckets[ruleID] = b
		return false
	}
	b.tokens -= 1.0
	r.buckets[ruleID] = b
	return true
}

func (r *RuleRateLimiter) pruneLocked(now time.Time) {
	if !r.lastPrune.IsZero() && now.Sub(r.lastPrune) < r.pruneWindow {
		return
	}
	r.lastPrune = now
	for k, b := range r.buckets {
		if now.Sub(b.last) > r.pruneWindow {
			delete(r.buckets, k)
		}
	}
}
