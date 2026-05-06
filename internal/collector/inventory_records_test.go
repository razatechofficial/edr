package collector

import (
	"path/filepath"
	"testing"
)

func TestPersistInventoryRecordsAndMaybeDelta(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	m := map[string]any{"package_count_est": 42, "listening_socket_rows_est": 3}
	cur := BuildInventoryRecordsFromSummary(m)
	rp, dp, err := PersistInventoryRecordsAndMaybeDelta(dir, cur, true)
	if err != nil {
		t.Fatal(err)
	}
	if rp == "" || filepath.Base(rp) != inventoryRecordsFile {
		t.Fatalf("records path %q", rp)
	}
	if dp == "" || filepath.Base(dp) != inventoryDeltaFile {
		t.Fatalf("delta path %q", dp)
	}
	cur2 := BuildInventoryRecordsFromSummary(map[string]any{"package_count_est": 99})
	_, dp2, err := PersistInventoryRecordsAndMaybeDelta(dir, cur2, true)
	if err != nil {
		t.Fatal(err)
	}
	if dp2 == "" {
		t.Fatal("expected delta path")
	}
}
