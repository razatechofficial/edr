package collector

import "testing"

func Test_pickLogReadOffset(t *testing.T) {
	if got := pickLogReadOffset(persistedLogOffset{Dev: 1, Ino: 2, Off: 100}, 1, 2, 500); got != 100 {
		t.Fatalf("same inode: got %d", got)
	}
	if got := pickLogReadOffset(persistedLogOffset{Dev: 1, Ino: 2, Off: 100}, 9, 2, 500); got != 0 {
		t.Fatalf("rotation dev change: got %d want 0", got)
	}
	if got := pickLogReadOffset(persistedLogOffset{Dev: 1, Ino: 2, Off: 100}, 1, 9, 500); got != 0 {
		t.Fatalf("rotation ino change: got %d want 0", got)
	}
	if got := pickLogReadOffset(persistedLogOffset{Off: 100}, 0, 0, 50); got != 0 {
		t.Fatalf("size clamp: got %d", got)
	}
	// legacy: no dev/ino on disk — still honor offset when platform returns zeros
	if got := pickLogReadOffset(persistedLogOffset{Off: 10}, 0, 0, 1000); got != 10 {
		t.Fatalf("legacy offset: got %d", got)
	}
}

func Test_loadPersistedLogOffsets_mixedJSON(t *testing.T) {
	raw := []byte(`{"/a.log": 42, "/b.log": {"dev":1,"ino":2,"off":99}}`)
	m := loadPersistedLogOffsets(raw)
	if m["/a.log"].Off != 42 || m["/a.log"].Dev != 0 {
		t.Fatalf("a: %+v", m["/a.log"])
	}
	if m["/b.log"].Off != 99 || m["/b.log"].Dev != 1 || m["/b.log"].Ino != 2 {
		t.Fatalf("b: %+v", m["/b.log"])
	}
}
