package forensics

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"go.uber.org/zap"
)

func writeAged(t *testing.T, dir, name string, size int, age time.Duration) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, make([]byte, size), 0o600); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
	when := time.Now().Add(-age)
	if err := os.Chtimes(path, when, when); err != nil {
		t.Fatalf("chtimes %s: %v", name, err)
	}
	return path
}

func TestEvidencePastTheRetentionWindowIsRemoved(t *testing.T) {
	dir := t.TempDir()
	old := writeAged(t, dir, "old.json", 10, 40*24*time.Hour)
	recent := writeAged(t, dir, "recent.json", 10, time.Hour)

	res, err := Sweep(dir, RetentionPolicy{MaxAge: 30 * 24 * time.Hour}, zap.NewNop())
	if err != nil {
		t.Fatalf("Sweep: %v", err)
	}
	if res.Removed != 1 {
		t.Fatalf("removed %d, want 1", res.Removed)
	}
	if _, err := os.Stat(old); !os.IsNotExist(err) {
		t.Error("expired evidence survived")
	}
	if _, err := os.Stat(recent); err != nil {
		t.Error("evidence inside the window was removed")
	}
}

// Age alone cannot stop one noisy day filling the disk, so the size bound has
// to bite independently — and it must discard oldest first so the newest
// evidence is the last thing to go.
func TestTheSizeBudgetDiscardsOldestFirst(t *testing.T) {
	dir := t.TempDir()
	writeAged(t, dir, "oldest.bin", 1000, 3*time.Hour)
	writeAged(t, dir, "middle.bin", 1000, 2*time.Hour)
	newest := writeAged(t, dir, "newest.bin", 1000, time.Hour)

	res, err := Sweep(dir, RetentionPolicy{MaxBytes: 1500}, zap.NewNop())
	if err != nil {
		t.Fatalf("Sweep: %v", err)
	}
	if res.Removed != 2 {
		t.Fatalf("removed %d, want 2 to get under budget", res.Removed)
	}
	if _, err := os.Stat(newest); err != nil {
		t.Error("the newest evidence was discarded first")
	}
	if res.RemainingSum > 1500 {
		t.Errorf("%d bytes remain, over the 1500 budget", res.RemainingSum)
	}
}

// A DFIR package is one piece of evidence however many files it holds, and is
// judged on when it finished rather than when it started.
func TestADirectoryIsMeasuredAndAgedAsAWhole(t *testing.T) {
	dir := t.TempDir()
	pkg := filepath.Join(dir, "dfir_alert_1")
	if err := os.MkdirAll(pkg, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	for _, n := range []string{"a.bin", "b.bin"} {
		if err := os.WriteFile(filepath.Join(pkg, n), make([]byte, 500), 0o600); err != nil {
			t.Fatalf("write: %v", err)
		}
	}
	// The directory's own mtime is old, but its contents are fresh.
	old := time.Now().Add(-40 * 24 * time.Hour)
	if err := os.Chtimes(pkg, old, old); err != nil {
		t.Fatalf("chtimes: %v", err)
	}

	res, err := Sweep(dir, RetentionPolicy{MaxAge: 30 * 24 * time.Hour}, zap.NewNop())
	if err != nil {
		t.Fatalf("Sweep: %v", err)
	}
	if res.Removed != 0 {
		t.Fatal("a package with fresh contents was aged out on its directory mtime")
	}
	if res.RemainingSum != 1000 {
		t.Errorf("directory measured as %d bytes, want 1000", res.RemainingSum)
	}
}

func TestAnUnboundedPolicyRemovesNothing(t *testing.T) {
	// Zero on both axes must mean "no limit", not "limit of zero" — the latter
	// would delete every piece of evidence on the host.
	dir := t.TempDir()
	writeAged(t, dir, "ancient.bin", 10_000, 365*24*time.Hour)

	res, err := Sweep(dir, RetentionPolicy{}, zap.NewNop())
	if err != nil {
		t.Fatalf("Sweep: %v", err)
	}
	if res.Removed != 0 {
		t.Fatalf("an unbounded policy removed %d entries", res.Removed)
	}
}

func TestAMissingDirectoryIsNotAnError(t *testing.T) {
	res, err := Sweep(filepath.Join(t.TempDir(), "never-created"), DefaultRetentionPolicy(), zap.NewNop())
	if err != nil {
		t.Fatalf("Sweep on a missing dir: %v", err)
	}
	if res.Removed != 0 {
		t.Error("something was removed from a directory that does not exist")
	}
}

func TestTheDefaultPolicyIsBoundedOnBothAxes(t *testing.T) {
	p := DefaultRetentionPolicy()
	if p.MaxAge <= 0 || p.MaxBytes <= 0 {
		t.Fatalf("default policy leaves an axis unbounded: %+v", p)
	}
	if err := p.Validate(); err != nil {
		t.Fatalf("the default policy does not validate: %v", err)
	}
	if err := (RetentionPolicy{MaxAge: -time.Hour}).Validate(); err == nil {
		t.Error("a negative age was accepted")
	}
	if err := (RetentionPolicy{MaxBytes: -1}).Validate(); err == nil {
		t.Error("a negative size was accepted")
	}
}
