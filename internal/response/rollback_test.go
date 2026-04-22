package response

import (
	"context"
	"testing"
	"time"
)

func TestRollback_RegisterAndRelease(t *testing.T) {
	t.Parallel()
	m := NewRollbackManager()
	called := false
	fn := func(_ context.Context) error {
		called = true
		return nil
	}
	c := Containment{ID: "c1", Action: ActionNetworkIsolate, RollbackFn: fn, Status: ContainmentActive}
	m.Register(c, fn)
	if err := m.Rollback(context.Background(), "c1"); err != nil {
		t.Fatal(err)
	}
	if !called {
		t.Fatal("rollback not called")
	}
}

func TestRollback_NonReversible(t *testing.T) {
	t.Parallel()
	m := NewRollbackManager()
	c := Containment{ID: "c2", Action: ActionAlert, RollbackFn: nil}
	m.Register(c, nil)
	err := m.Rollback(context.Background(), "c2")
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestRollback_Expiry(t *testing.T) {
	t.Parallel()
	m := NewRollbackManager()
	var ran int
	c := Containment{ID: "c3", Action: ActionNetworkIsolate, ExpiresAt: time.Now().Add(-time.Second), RollbackFn: func(_ context.Context) error {
		ran++
		return nil
	}}
	m.Register(c, c.RollbackFn)
	m.RunExpiredOnce(context.Background())
	if ran != 1 {
		t.Fatalf("ran=%d", ran)
	}
}

func TestReleaseViaStandardLayer(t *testing.T) {
	t.Parallel()
	// Exercises [standardLayer] RegisterContainment + Release through concrete type
	sl := &standardLayer{
		rm:   NewRollbackManager(),
		cmap: make(map[string]Containment),
	}
	exec := 0
	fn := func(_ context.Context) error { exec++; return nil }
	sl.RegisterContainment(Containment{ID: "r1", Status: ContainmentActive, RollbackFn: fn})
	if err := sl.Release("r1"); err != nil {
		t.Fatal(err)
	}
	if exec != 1 {
		t.Fatalf("exec=%d", exec)
	}
}
