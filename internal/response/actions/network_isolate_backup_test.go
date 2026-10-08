//go:build linux || darwin

package actions

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The backup used to be written by `sh -c "iptables-save > /tmp/edr_iptables.bak"`.
// A world-writable directory lets anyone pre-create that path as a symlink, and
// the redirection would then truncate whatever it pointed at, as root.
func TestASymlinkInThePlaceOfTheBackupIsRefused(t *testing.T) {
	dir := t.TempDir()
	victim := filepath.Join(dir, "victim")
	if err := os.WriteFile(victim, []byte("important"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	backup := filepath.Join(dir, "iptables.bak")
	if err := os.Symlink(victim, backup); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}

	err := saveIPTables(context.Background(), backup)
	if err == nil {
		t.Fatal("a symlink in the backup path was accepted")
	}
	if !strings.Contains(err.Error(), "not a regular file") {
		t.Errorf("err = %v; want the symlink named as the reason", err)
	}
	// The thing it pointed at must be untouched.
	data, readErr := os.ReadFile(victim)
	if readErr != nil || string(data) != "important" {
		t.Error("the symlink target was modified")
	}
}

// Releasing a host used to report success when the backup was missing, leaving
// it isolated with nothing indicating why.
func TestRestoringWithoutABackupReportsFailure(t *testing.T) {
	err := restoreIPTables(context.Background(), filepath.Join(t.TempDir(), "absent.bak"))
	if err == nil {
		t.Fatal("restoring from a missing backup reported success")
	}
}

func TestTheDefaultBackupPathIsNotAShotInTheDark(t *testing.T) {
	t.Setenv("EDR_DATA_DIR", "/var/lib/edr")
	if got := defaultIsolateBackupPath(); got != filepath.Join("/var/lib/edr", "iptables.bak") {
		t.Errorf("path = %q, want it under the data directory", got)
	}

	// Without a data directory it must still not sit directly in a shared
	// temporary directory where anyone can pre-create it.
	t.Setenv("EDR_DATA_DIR", "")
	got := defaultIsolateBackupPath()
	if filepath.Dir(got) == os.TempDir() {
		t.Errorf("fallback %q sits directly in the shared temp directory", got)
	}
}

func TestAStaleRegularBackupIsReplaced(t *testing.T) {
	// A previous isolation leaves a backup behind; the next one must be able to
	// overwrite it, or isolation would fail from the second time onwards.
	dir := t.TempDir()
	backup := filepath.Join(dir, "iptables.bak")
	if err := os.WriteFile(backup, []byte("old ruleset"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	err := saveIPTables(context.Background(), backup)
	// iptables-save is absent on the test host, so the command fails — but it
	// must get as far as running it, not refuse on the stale file.
	if err != nil && strings.Contains(err.Error(), "not a regular file") {
		t.Fatalf("a stale regular backup was refused: %v", err)
	}
}
