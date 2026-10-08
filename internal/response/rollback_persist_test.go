package response

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"go.uber.org/zap"
)

// A restart used to orphan every active containment: the expiry timers died
// with the process and nothing recorded that a host was still isolated. That is
// worse than never isolating, because it is silent and permanent.
func TestContainmentsSurviveARestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "containments.json")

	first := NewPersistentRollbackManager(path, zap.NewNop())
	first.Register(Containment{
		ID:           "c-1",
		HostID:       "host-a",
		Action:       ActionNetworkBlock,
		Target:       "198.51.100.7:4444",
		ExpiresAt:    time.Now().Add(30 * time.Minute),
		RollbackArgv: []string{"/bin/true"},
	}, func(context.Context) error { return nil })

	if _, err := os.Stat(path); err != nil {
		t.Fatalf("nothing was persisted: %v", err)
	}

	// A new process reading the same file.
	second := NewPersistentRollbackManager(path, zap.NewNop())
	active := second.Active()
	if len(active) != 1 {
		t.Fatalf("recovered %d containments, want 1", len(active))
	}
	got := active[0]
	if got.ContainmentID != "c-1" || got.Target != "198.51.100.7:4444" {
		t.Errorf("recovered record lost its identity: %+v", got)
	}
	if !got.Reversible {
		t.Error("a containment with a recorded command came back unliftable")
	}
}

// The point of surviving is that the expiry still fires.
func TestARecoveredContainmentStillExpires(t *testing.T) {
	path := filepath.Join(t.TempDir(), "containments.json")

	first := NewPersistentRollbackManager(path, zap.NewNop())
	first.Register(Containment{
		ID:           "c-expired",
		Action:       ActionNetworkBlock,
		Target:       "198.51.100.7:4444",
		ExpiresAt:    time.Now().Add(-time.Minute),
		RollbackArgv: []string{"/bin/true"},
	}, func(context.Context) error { return nil })

	second := NewPersistentRollbackManager(path, zap.NewNop())
	second.RunExpiredOnce(context.Background())

	if n := len(second.Active()); n != 0 {
		t.Fatalf("%d containments survived their expiry after a restart", n)
	}
	// And the file reflects it, so a third start does not resurrect them.
	third := NewPersistentRollbackManager(path, zap.NewNop())
	if n := len(third.Active()); n != 0 {
		t.Fatalf("expired containment came back on the next start (%d)", n)
	}
}

// A containment whose undo cannot be expressed as a command must still be
// visible — an operator has to know what to lift by hand.
func TestAnUnliftableContainmentIsStillReported(t *testing.T) {
	path := filepath.Join(t.TempDir(), "containments.json")

	first := NewPersistentRollbackManager(path, zap.NewNop())
	first.Register(Containment{
		ID:        "c-opaque",
		Action:    ActionFileQuarantine,
		Target:    "/tmp/suspect",
		ExpiresAt: time.Now().Add(time.Hour),
	}, func(context.Context) error { return nil })

	second := NewPersistentRollbackManager(path, zap.NewNop())
	active := second.Active()
	if len(active) != 1 {
		t.Fatalf("recovered %d, want the record retained for reporting", len(active))
	}
	if active[0].Reversible {
		t.Error("a record with no recorded command claimed to be reversible")
	}
	if active[0].Target != "/tmp/suspect" {
		t.Errorf("target lost: %q", active[0].Target)
	}
}

func TestDeletingAContainmentIsPersisted(t *testing.T) {
	path := filepath.Join(t.TempDir(), "containments.json")

	first := NewPersistentRollbackManager(path, zap.NewNop())
	first.Register(Containment{ID: "c-1", RollbackArgv: []string{"/bin/true"}},
		func(context.Context) error { return nil })
	first.Delete("c-1")

	if n := len(NewPersistentRollbackManager(path, zap.NewNop()).Active()); n != 0 {
		t.Fatalf("a deleted containment came back (%d)", n)
	}
}

// A truncated or corrupt file must not stop the agent starting: an endpoint
// with no agent is worse than one with forgotten containments.
func TestACorruptStoreDoesNotPreventStartup(t *testing.T) {
	path := filepath.Join(t.TempDir(), "containments.json")
	if err := os.WriteFile(path, []byte("{not json"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	m := NewPersistentRollbackManager(path, zap.NewNop())
	if m == nil {
		t.Fatal("a corrupt store prevented the manager from being created")
	}
	if n := len(m.Active()); n != 0 {
		t.Errorf("corrupt store produced %d records", n)
	}
}

func TestTheStoreIsNotWorldReadable(t *testing.T) {
	// The records name isolated hosts, blocked addresses and quarantined paths.
	path := filepath.Join(t.TempDir(), "containments.json")
	m := NewPersistentRollbackManager(path, zap.NewNop())
	m.Register(Containment{ID: "c-1", RollbackArgv: []string{"/bin/true"}},
		func(context.Context) error { return nil })

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if perm := info.Mode().Perm(); perm&0o077 != 0 {
		t.Errorf("mode = %04o, want no group or other access", perm)
	}
}
