package installprogress

import "testing"

func TestIndex(t *testing.T) {
	if got := Index("reqs", 3); got != 0 {
		t.Fatalf("reqs=%d", got)
	}
	if got := Index("pkg", 3); got != 1 {
		t.Fatalf("pkg=%d", got)
	}
	if got := Index("daemon", 3); got != 2 {
		t.Fatalf("daemon=%d", got)
	}
	if got := Index("done", 3); got != 3 {
		t.Fatalf("done=%d", got)
	}
	if got := Index("fail", 3); got != -1 {
		t.Fatalf("fail=%d", got)
	}
}

func TestWriteReadClear(t *testing.T) {
	Clear()
	Write("pkg")
	if Read() != "pkg" {
		t.Fatalf("read=%q", Read())
	}
	Clear()
	if Read() != "" {
		t.Fatalf("expected empty after clear")
	}
}
