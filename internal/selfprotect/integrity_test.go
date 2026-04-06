package selfprotect

import (
	"os"
	"path/filepath"
	"testing"

	"go.uber.org/zap"
)

func TestIntegrityCheckerBaseline(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	backupDir := t.TempDir()

	files := make([]string, 3)
	for i := range files {
		p := filepath.Join(dir, "file-"+string(rune('a'+i))+".bin")
		if err := os.WriteFile(p, []byte("content-"+string(rune('a'+i))), 0644); err != nil {
			t.Fatalf("write test file: %v", err)
		}
		files[i] = p
	}

	checker, err := NewIntegrityChecker(files, backupDir, zap.NewNop())
	if err != nil {
		t.Fatalf("NewIntegrityChecker: %v", err)
	}

	violations, err := checker.Check()
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if len(violations) != 0 {
		t.Errorf("expected 0 violations at baseline, got %d", len(violations))
	}

	entries, err := os.ReadDir(backupDir)
	if err != nil {
		t.Fatalf("read backup dir: %v", err)
	}
	if len(entries) != len(files) {
		t.Errorf("expected %d backup files, got %d", len(files), len(entries))
	}
}

func TestIntegrityCheckerDetectsModification(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	backupDir := t.TempDir()
	tracked := filepath.Join(dir, "binary.exe")
	if err := os.WriteFile(tracked, []byte("original-binary"), 0644); err != nil {
		t.Fatalf("write: %v", err)
	}

	checker, err := NewIntegrityChecker([]string{tracked}, backupDir, zap.NewNop())
	if err != nil {
		t.Fatalf("NewIntegrityChecker: %v", err)
	}

	if err := os.WriteFile(tracked, []byte("MODIFIED-binary"), 0644); err != nil {
		t.Fatalf("tamper: %v", err)
	}

	violations, err := checker.Check()
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if len(violations) != 1 {
		t.Fatalf("expected 1 violation, got %d", len(violations))
	}
	if violations[0].Path != tracked {
		t.Errorf("violation path = %q, want %q", violations[0].Path, tracked)
	}
	if violations[0].ExpectedHash == violations[0].ActualHash {
		t.Error("expected hashes to differ after modification")
	}
}

func TestIntegrityCheckerNoFalsePositive(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	backupDir := t.TempDir()

	files := make([]string, 5)
	for i := range files {
		p := filepath.Join(dir, "stable-"+string(rune('0'+i))+".dat")
		if err := os.WriteFile(p, []byte("stable-content"), 0644); err != nil {
			t.Fatalf("write: %v", err)
		}
		files[i] = p
	}

	checker, err := NewIntegrityChecker(files, backupDir, zap.NewNop())
	if err != nil {
		t.Fatalf("NewIntegrityChecker: %v", err)
	}

	for range 10 {
		violations, err := checker.Check()
		if err != nil {
			t.Fatalf("Check: %v", err)
		}
		if len(violations) != 0 {
			t.Fatalf("false positive: got %d violations on unmodified files", len(violations))
		}
	}
}
