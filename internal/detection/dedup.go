package detection

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sync"
	"time"
)

type AlertDeduper struct {
	window time.Duration
	seen   map[string]time.Time
	mu     sync.Mutex
}

func NewAlertDeduper(window time.Duration) *AlertDeduper {
	if window <= 0 {
		window = 5 * time.Minute
	}
	return &AlertDeduper{
		window: window,
		seen:   make(map[string]time.Time),
	}
}

func (d *AlertDeduper) IsDuplicate(det Detection) bool {
	key := dedupKey(det)
	now := time.Now().UTC()
	d.mu.Lock()
	defer d.mu.Unlock()
	if ts, ok := d.seen[key]; ok && now.Sub(ts) < d.window {
		return true
	}
	d.seen[key] = now
	return false
}

func dedupKey(det Detection) string {
	raw := fmt.Sprintf("%s|%s|%s|%s", det.RuleID, extractHost(det.Event), det.TechniqueID, extractPIDString(det.Event))
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}

func extractPIDString(event interface{}) string {
	m, ok := event.(map[string]interface{})
	if !ok {
		return "0"
	}
	if v, ok := m["pid"]; ok {
		return fmt.Sprint(v)
	}
	return "0"
}
