package response

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/razatechofficial/edr/internal/schema"
)

func TestKillSelfBlocked(t *testing.T) {
	r := NewResponder(true, []string{"systemd"})
	res := r.Execute(schema.ResponseCommand{
		Action:     schema.ResponseKillProcess,
		ProcessPID: os.Getpid(),
	})
	if res.Success {
		t.Fatal("expected self kill to be blocked")
	}
}

func TestQuarantineFile(t *testing.T) {
	dir := t.TempDir()
	oldWd, _ := os.Getwd()
	_ = os.Chdir(dir)
	defer func() { _ = os.Chdir(oldWd) }()

	src := filepath.Join(dir, "sample.bin")
	if err := os.WriteFile(src, []byte("x"), 0o600); err != nil {
		t.Fatalf("write src: %v", err)
	}

	res := quarantineFile(schema.ResponseCommand{
		Action:   schema.ResponseQuarantine,
		FilePath: src,
	})
	if !res.Success {
		t.Fatalf("expected quarantine success, got: %s", res.Message)
	}
}

func TestKillSpawnedProcess(t *testing.T) {
	r := NewResponder(true, nil)
	cmd := spawnSleepProcess(t)
	pid := cmd.Process.Pid

	res := r.Execute(schema.ResponseCommand{
		Action:      schema.ResponseKillProcess,
		ProcessPID:  pid,
		ProcessName: "sleep",
	})
	if !res.Success {
		t.Fatalf("expected kill success, got: %s", res.Message)
	}

	done := make(chan error, 1)
	go func() {
		done <- cmd.Wait()
	}()

	select {
	case <-time.After(2 * time.Second):
		t.Fatalf("expected pid %d to exit after kill", pid)
	case <-done:
		return
	}
}

func spawnSleepProcess(t *testing.T) *exec.Cmd {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("spawn/kill test is unix-only")
	}
	cmd := exec.Command("sleep", "30")
	if err := cmd.Start(); err != nil {
		t.Fatalf("start child process: %v", err)
	}
	t.Cleanup(func() {
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
		}
	})
	return cmd
}
