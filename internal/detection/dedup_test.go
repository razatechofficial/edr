package detection

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestAlertDeduperSuppressAndDrain(t *testing.T) {
	d := NewAlertDeduper(100*time.Millisecond, "")
	base := Detection{
		RuleID:      "r1",
		TechniqueID: "T1055",
		Event: &EventPayload{Unstructured: map[string]interface{}{
			"hostname": "h1", "pid": 42,
		}},
	}
	if d.IsDuplicate(base) {
		t.Fatal("first should not duplicate")
	}
	if !d.IsDuplicate(base) {
		t.Fatal("second should duplicate")
	}
	sums := d.DrainExpired()
	if len(sums) != 0 {
		t.Fatalf("no drain before window elapses")
	}
	time.Sleep(120 * time.Millisecond)
	sums = d.DrainExpired()
	if len(sums) != 1 || sums[0].Source != SourceDedup {
		t.Fatalf("expected dedup summary, got %+v", sums)
	}
}

func TestAlertDeduperPersistRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "dedup_state.json")
	d1 := NewAlertDeduper(1*time.Hour, dir)
	_ = d1.IsDuplicate(Detection{
		RuleID: "persist-rule", TechniqueID: "T1",
		Event: &EventPayload{Unstructured: map[string]interface{}{"hostname": "x", "pid": 1}},
	})
	if err := d1.persistState(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatal(err)
	}
	d2 := NewAlertDeduper(1*time.Hour, dir)
	// Same key should duplicate after reload
	dup := Detection{
		RuleID: "persist-rule", TechniqueID: "T1",
		Event: &EventPayload{Unstructured: map[string]interface{}{"hostname": "x", "pid": 1}},
	}
	if !d2.IsDuplicate(dup) {
		t.Fatal("expected duplicate after state restore")
	}
}
