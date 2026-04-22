package detection

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/google/uuid"
)

// DedupEntry tracks duplicate suppression for a single dedup key within a time window.
type DedupEntry struct {
	FirstSeen       time.Time `json:"first_seen"`
	LastSeen        time.Time `json:"last_seen"`
	SuppressedCount uint64    `json:"suppressed_count"`
	RuleID          string    `json:"rule_id,omitempty"`
}

type AlertDeduper struct {
	window     time.Duration
	seen       map[string]*DedupEntry
	mu         sync.Mutex
	persistPath string
	persistStop chan struct{}
	persistOnce sync.Once
}

// NewAlertDeduper creates a deduplicator. dataDir, if non-empty, enables
// load/save of dedup_state.json and a 60s persistence ticker (after Start).
func NewAlertDeduper(window time.Duration, dataDir string) *AlertDeduper {
	if window <= 0 {
		window = 5 * time.Minute
	}
	d := &AlertDeduper{
		window: window,
		seen:   make(map[string]*DedupEntry),
	}
	if dataDir != "" {
		_ = os.MkdirAll(dataDir, 0o700)
		d.persistPath = filepath.Join(dataDir, "dedup_state.json")
		d.persistStop = make(chan struct{})
		_ = d.loadState()
	}
	return d
}

// Start begins the 60s persistence background loop. No-op if dataDir was empty.
func (d *AlertDeduper) Start() {
	if d.persistPath == "" || d.persistStop == nil {
		return
	}
	d.persistOnce.Do(func() {
		go d.persistLoop()
	})
}

// Stop flushes state to disk and ends the persistence loop.
func (d *AlertDeduper) Stop() {
	if d.persistPath == "" || d.persistStop == nil {
		return
	}
	select {
	case <-d.persistStop:
	default:
		close(d.persistStop)
	}
	_ = d.persistState()
}

func (d *AlertDeduper) persistLoop() {
	tick := time.NewTicker(60 * time.Second)
	defer tick.Stop()
	for {
		select {
		case <-d.persistStop:
			return
		case <-tick.C:
			_ = d.persistState()
		}
	}
}

func (d *AlertDeduper) loadState() error {
	data, err := os.ReadFile(d.persistPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	var snap map[string]DedupEntry
	if err := json.Unmarshal(data, &snap); err != nil {
		return err
	}
	now := time.Now().UTC()
	d.mu.Lock()
	defer d.mu.Unlock()
	for k, v := range snap {
		if v.FirstSeen.IsZero() {
			continue
		}
		if now.Sub(v.FirstSeen) < d.window {
			d.seen[k] = &DedupEntry{
				FirstSeen:       v.FirstSeen,
				LastSeen:        v.LastSeen,
				SuppressedCount: v.SuppressedCount,
				RuleID:          v.RuleID,
			}
		}
	}
	return nil
}

func (d *AlertDeduper) persistState() error {
	if d.persistPath == "" {
		return nil
	}
	d.mu.Lock()
	snap := make(map[string]DedupEntry, len(d.seen))
	for k, v := range d.seen {
		if v == nil {
			continue
		}
		snap[k] = *v
	}
	d.mu.Unlock()
	data, err := json.Marshal(snap)
	if err != nil {
		return err
	}
	return os.WriteFile(d.persistPath, data, 0o600)
}

// IsDuplicate returns true if this detection was seen within the suppression window.
// First sighting returns false and records the key.
func (d *AlertDeduper) IsDuplicate(det Detection) bool {
	key := dedupKey(det)
	now := time.Now().UTC()
	d.mu.Lock()
	defer d.mu.Unlock()
	if ent, ok := d.seen[key]; ok {
		if now.Sub(ent.FirstSeen) < d.window {
			ent.LastSeen = now
			ent.SuppressedCount++
			return true
		}
		delete(d.seen, key)
	}
	d.seen[key] = &DedupEntry{
		FirstSeen: now,
		LastSeen:  now,
		RuleID:    det.RuleID,
	}
	return false
}

// DrainExpired removes entries whose window has ended and returns summary
// detections for keys that had suppressions.
func (d *AlertDeduper) DrainExpired() []Detection {
	now := time.Now().UTC()
	d.mu.Lock()
	defer d.mu.Unlock()
	var out []Detection
	for k, ent := range d.seen {
		if ent == nil {
			delete(d.seen, k)
			continue
		}
		if now.Sub(ent.FirstSeen) < d.window {
			continue
		}
		if ent.SuppressedCount > 0 {
			rid := ent.RuleID
			if rid == "" {
				rid = "dedup"
			}
			suffix := k
			if len(suffix) > 16 {
				suffix = suffix[:16]
			}
			out = append(out, Detection{
				ID:          uuid.New().String(),
				Timestamp:   now,
				RuleID:      "dedup-" + suffix,
				RuleName:    "Alert deduplication",
				Severity:    P3,
				Confidence:  1.0,
				Source:      SourceDedup,
				Description: fmt.Sprintf("suppressed %d duplicate alerts for rule %s", ent.SuppressedCount, rid),
				Tags:        []string{"dedup", "suppressed_summary"},
			})
		}
		delete(d.seen, k)
	}
	return out
}

func dedupKey(det Detection) string {
	raw := fmt.Sprintf("%s|%s|%s|%s", det.RuleID, eventPayloadHost(det.Event), det.TechniqueID, eventPayloadPIDString(det.Event))
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}

