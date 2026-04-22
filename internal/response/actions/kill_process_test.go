package actions

import (
	"context"
	"os"
	"os/exec"
	"runtime"
	"syscall"
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
	time.Sleep(100 * time.Millisecond)
	p, err := os.FindProcess(int(pid))
	if err != nil {
		return
	}
	if err := p.Signal(syscall.Signal(0)); err == nil {
		t.Fatal("expected process to be gone")
	}
	_ = p.Release()
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
	k := &KillProcessAction{PID: ppid, IncludeChildren: true}
	if err := k.Execute(ctx); err != nil {
		t.Fatal(err)
	}
}
