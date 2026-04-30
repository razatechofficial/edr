package actions

import (
	"context"
	"os/exec"
	"runtime"
	"testing"
	"time"
)

func TestKillProcessAction_Basic(t *testing.T) {
	if testing.Short() {
		t.Skip("spawns process")
	}
	if runtime.GOOS == "windows" {
		t.Skip("uses unix sleep")
	}
	t.Parallel()
	ctx := context.Background()
	cmd := exec.CommandContext(ctx, "sleep", "600")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	pid := uint32(cmd.Process.Pid)
	k := &KillProcessAction{PID: pid, IncludeChildren: false}
	if err := k.Execute(ctx); err != nil {
		t.Fatal(err)
	}
	waitErr := make(chan error, 1)
	go func() { waitErr <- cmd.Wait() }()
	select {
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for killed process to exit")
	case err := <-waitErr:
		if err == nil {
			t.Fatal("expected kill to produce wait error, got nil")
		}
	}
}

func TestKillProcessAction_IncludeChildren(t *testing.T) {
	if testing.Short() {
		t.Skip("spawns process")
	}
	if runtime.GOOS == "windows" {
		t.Skip("unix test")
	}
	t.Parallel()
	ctx := context.Background()
	// Long-running parent so we can collect children
	parent := exec.CommandContext(ctx, "sh", "-c", "sleep 600 & sleep 600 & wait")
	if err := parent.Start(); err != nil {
		t.Fatal(err)
	}
	ppid := uint32(parent.Process.Pid)
	children, err := getChildPIDs(ctx, ppid)
	if err != nil || len(children) < 1 {
		_ = parent.Process.Kill()
		_, _ = parent.Process.Wait()
		t.Skip("no child PIDs visible for tree-kill test")
	}
	k := &KillProcessAction{PID: ppid, IncludeChildren: true}
	if err := k.Execute(ctx); err != nil {
		t.Fatal(err)
	}
	time.Sleep(200 * time.Millisecond)
	for _, cpid := range children {
		if verifyPIDExists(cpid) {
			t.Fatalf("child %d still live after tree kill (include_children)", cpid)
		}
	}
}
