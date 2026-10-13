package forensics

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

func write(t *testing.T, dir, name string, data []byte, mod time.Time) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
	if !mod.IsZero() {
		if err := os.Chtimes(path, mod, mod); err != nil {
			t.Fatalf("chtimes: %v", err)
		}
	}
	return path
}

func digestOf(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func TestScanDirHashesWhatItFinds(t *testing.T) {
	dir := t.TempDir()
	payload := []byte("a dropped executable")
	write(t, dir, "update.exe", payload, time.Time{})

	recs := scanDir(context.Background(), dir, DefaultFileScanLimits(), time.Now().Add(time.Minute))
	if len(recs) != 1 {
		t.Fatalf("%d records", len(recs))
	}
	// The digest is the whole point: by the time this bundle is read the file
	// is usually gone, and a path alone leads nowhere.
	if recs[0].SHA256 != digestOf(payload) {
		t.Fatalf("digest %q", recs[0].SHA256)
	}
	if recs[0].Size != int64(len(payload)) {
		t.Fatalf("size %d", recs[0].Size)
	}
	if recs[0].ModTime.IsZero() || recs[0].Mode == "" {
		t.Fatalf("metadata missing: %+v", recs[0])
	}
	if recs[0].Skipped != "" {
		t.Fatalf("unexpectedly skipped: %q", recs[0].Skipped)
	}
}

func TestScanDirKeepsTheNewestFilesWhenItHasToChoose(t *testing.T) {
	dir := t.TempDir()
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	write(t, dir, "ancient.bin", []byte("old"), base)
	write(t, dir, "yesterday.bin", []byte("mid"), base.Add(48*time.Hour))
	write(t, dir, "justnow.bin", []byte("new"), base.Add(72*time.Hour))

	limits := DefaultFileScanLimits()
	limits.MaxFiles = 2
	recs := scanDir(context.Background(), dir, limits, time.Now().Add(time.Minute))
	if len(recs) != 2 {
		t.Fatalf("%d records, expected 2", len(recs))
	}
	// Newest first: the cap must not drop the dropper and keep a stale cache
	// file.
	if filepath.Base(recs[0].Path) != "justnow.bin" {
		t.Fatalf("first record %q", recs[0].Path)
	}
	if filepath.Base(recs[1].Path) != "yesterday.bin" {
		t.Fatalf("second record %q", recs[1].Path)
	}
}

func TestScanDirNamesAFileItWouldNotHash(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "huge.bin", []byte("0123456789"), time.Time{})
	limits := DefaultFileScanLimits()
	limits.MaxHashBytes = 4

	recs := scanDir(context.Background(), dir, limits, time.Now().Add(time.Minute))
	if len(recs) != 1 {
		t.Fatalf("%d records", len(recs))
	}
	// Still named, sized and timestamped. Dropping it would hide that it was
	// there at all, which is worse than reporting it unhashed.
	if recs[0].SHA256 != "" {
		t.Fatal("a file over the hash limit was hashed anyway")
	}
	if recs[0].Skipped == "" {
		t.Fatal("no reason was given for the missing digest")
	}
	if recs[0].Size != 10 {
		t.Fatalf("size %d", recs[0].Size)
	}
}

func TestScanDirDoesNotFollowASymlink(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation needs privilege on windows")
	}
	dir := t.TempDir()
	secret := filepath.Join(t.TempDir(), "secret.txt")
	if err := os.WriteFile(secret, []byte("not the agent's to read"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := os.Symlink(secret, filepath.Join(dir, "innocent.txt")); err != nil {
		t.Fatalf("symlink: %v", err)
	}

	recs := scanDir(context.Background(), dir, DefaultFileScanLimits(), time.Now().Add(time.Minute))
	if len(recs) != 1 {
		t.Fatalf("%d records", len(recs))
	}
	// A link planted in a world-writable directory must not have the agent
	// read, and put into evidence, whatever it points at.
	if recs[0].SHA256 != "" {
		t.Fatal("the collector followed a symlink and hashed the target")
	}
	if recs[0].Symlink != secret {
		t.Fatalf("the link target was not recorded: %q", recs[0].Symlink)
	}
}

func TestScanDirSkipsDirectories(t *testing.T) {
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, "nested"), 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	recs := scanDir(context.Background(), dir, DefaultFileScanLimits(), time.Now().Add(time.Minute))
	if len(recs) != 1 || recs[0].Skipped != "directory" {
		t.Fatalf("records: %+v", recs)
	}
}

func TestScanDirRecordsFilesAfterTheBudgetIsSpent(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "a.bin", []byte("one"), time.Time{})
	write(t, dir, "b.bin", []byte("two"), time.Time{})

	// A deadline already in the past: nothing gets hashed, everything is still
	// named, so a reader can tell a bounded scan from an empty directory.
	recs := scanDir(context.Background(), dir, DefaultFileScanLimits(), time.Now().Add(-time.Minute))
	if len(recs) != 2 {
		t.Fatalf("%d records", len(recs))
	}
	for _, r := range recs {
		if r.SHA256 != "" {
			t.Fatal("a file was hashed after the budget was spent")
		}
		if r.Skipped == "" {
			t.Fatalf("no reason given for %q", r.Path)
		}
	}
}

func TestScanDirStopsOnACancelledContext(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "a.bin", []byte("one"), time.Time{})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	recs := scanDir(ctx, dir, DefaultFileScanLimits(), time.Now().Add(time.Minute))
	if len(recs) != 1 || recs[0].SHA256 != "" {
		t.Fatalf("records: %+v", recs)
	}
}

func TestScanDirToleratesAMissingDirectory(t *testing.T) {
	recs := scanDir(context.Background(), filepath.Join(t.TempDir(), "absent"),
		DefaultFileScanLimits(), time.Now().Add(time.Minute))
	if recs != nil {
		t.Fatalf("records for a missing directory: %+v", recs)
	}
}

func TestStatFileRecordsAKnownPath(t *testing.T) {
	dir := t.TempDir()
	payload := []byte("browser history")
	path := write(t, dir, "History", payload, time.Time{})

	rec, ok := statFile(context.Background(), path, DefaultFileScanLimits(), time.Now().Add(time.Minute))
	if !ok {
		t.Fatal("a file that exists was not recorded")
	}
	if rec.SHA256 != digestOf(payload) {
		t.Fatalf("digest %q", rec.SHA256)
	}
}

func TestStatFileReportsAMissingPathAsAbsent(t *testing.T) {
	if _, ok := statFile(context.Background(), filepath.Join(t.TempDir(), "nope"),
		DefaultFileScanLimits(), time.Now().Add(time.Minute)); ok {
		t.Fatal("a missing file was recorded as present")
	}
}

func TestLimitsFallBackToDefaults(t *testing.T) {
	got := FileScanLimits{}.withDefaults()
	want := DefaultFileScanLimits()
	if got != want {
		t.Fatalf("limits %+v, expected %+v", got, want)
	}
}

func TestPathsReducesRecordsForTheOlderFormat(t *testing.T) {
	recs := []FileRecord{{Path: "/a"}, {Path: "/b"}}
	got := Paths(recs)
	if len(got) != 2 || got[0] != "/a" || got[1] != "/b" {
		t.Fatalf("paths %v", got)
	}
	if Paths(nil) == nil || len(Paths(nil)) != 0 {
		t.Fatal("nil records should produce an empty, non-nil slice")
	}
}
