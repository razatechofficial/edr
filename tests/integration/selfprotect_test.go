//go:build integration

package integration

import (
	"os"
	"testing"

	"github.com/razatechofficial/edr/internal/selfprotect"
	"github.com/razatechofficial/edr/internal/testutil"
	"go.uber.org/zap"
)

func TestIntegrityCheckerDetectsTampering(t *testing.T) {
	dir := t.TempDir()
	backupDir := t.TempDir()

	tracked := testutil.MustCreateTempFile(t, dir, "binary-*.exe", "original binary content")

	logger := zap.NewNop()
	checker, err := selfprotect.NewIntegrityChecker([]string{tracked}, backupDir, t.TempDir(), logger)
	if err != nil {
		t.Fatalf("NewIntegrityChecker: %v", err)
	}

	violations, err := checker.Check()
	if err != nil {
		t.Fatalf("Check (initial): %v", err)
	}
	if len(violations) != 0 {
		t.Fatalf("expected 0 violations before tampering, got %d", len(violations))
	}

	if err := os.WriteFile(tracked, []byte("tampered binary content!!!"), 0644); err != nil {
		t.Fatalf("tamper file: %v", err)
	}

	violations, err = checker.Check()
	if err != nil {
		t.Fatalf("Check (after tamper): %v", err)
	}
	if len(violations) != 1 {
		t.Fatalf("expected 1 violation after tampering, got %d", len(violations))
	}

	v := violations[0]
	if v.Path != tracked {
		t.Errorf("violation path = %q, want %q", v.Path, tracked)
	}
	if v.ExpectedHash == v.ActualHash {
		t.Error("expected different hashes after tampering")
	}
}

func TestIntegrityCheckerRestore(t *testing.T) {
	dir := t.TempDir()
	backupDir := t.TempDir()

	originalContent := "original content for restore test"
	tracked := testutil.MustCreateTempFile(t, dir, "restore-*.bin", originalContent)

	logger := zap.NewNop()
	checker, err := selfprotect.NewIntegrityChecker([]string{tracked}, backupDir, t.TempDir(), logger)
	if err != nil {
		t.Fatalf("NewIntegrityChecker: %v", err)
	}

	if err := os.WriteFile(tracked, []byte("corrupted"), 0644); err != nil {
		t.Fatalf("tamper file: %v", err)
	}

	if err := checker.Restore(tracked); err != nil {
		t.Fatalf("Restore: %v", err)
	}

	restored, err := os.ReadFile(tracked)
	if err != nil {
		t.Fatalf("read restored file: %v", err)
	}
	if string(restored) != originalContent {
		t.Errorf("restored content = %q, want %q", restored, originalContent)
	}

	violations, err := checker.Check()
	if err != nil {
		t.Fatalf("Check (after restore): %v", err)
	}
	if len(violations) != 0 {
		t.Errorf("expected 0 violations after restore, got %d", len(violations))
	}
}

func TestWatchdogHealth(t *testing.T) {
	t.Skip("watchdog requires Unix domain socket and agent binary; skipped in CI")
}
