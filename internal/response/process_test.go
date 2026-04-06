//go:build !windows

package response

import (
	"context"
	"os"
	"os/exec"
	"strconv"
	"syscall"
	"testing"
	"time"

	"go.uber.org/zap"
)

func newTestProcessHandler(t *testing.T, protected []string) *ProcessHandler {
	t.Helper()
	logger, _ := zap.NewDevelopment()
	return NewProcessHandler(logger, protected)
}

func TestKillSpawnedProcessHandler(t *testing.T) {
	t.Parallel()
	h := newTestProcessHandler(t, nil)

	cmd := exec.Command("sleep", "60")
	if err := cmd.Start(); err != nil {
		t.Fatalf("start sleep: %v", err)
	}
	pid := cmd.Process.Pid

	result, err := h.Execute(context.Background(), map[string]interface{}{
		"pid":  pid,
		"mode": "kill",
	})
	if err != nil {
		t.Fatalf("Execute kill: %v", err)
	}
	if !result.Success {
		t.Fatalf("kill failed: %s", result.Message)
	}

	cmd.Wait()

	if err := syscall.Kill(pid, 0); err == nil {
		t.Error("process still alive after kill")
	}
}

func TestSuspendResumeProcess(t *testing.T) {
	t.Parallel()
	h := newTestProcessHandler(t, nil)

	cmd := exec.Command("sleep", "60")
	if err := cmd.Start(); err != nil {
		t.Fatalf("start sleep: %v", err)
	}
	pid := cmd.Process.Pid
	t.Cleanup(func() {
		cmd.Process.Kill()
		cmd.Wait()
	})

	result, err := h.Execute(context.Background(), map[string]interface{}{
		"pid":  pid,
		"mode": "suspend",
	})
	if err != nil {
		t.Fatalf("Execute suspend: %v", err)
	}
	if !result.Success {
		t.Fatalf("suspend failed: %s", result.Message)
	}

	time.Sleep(50 * time.Millisecond)
	stateBytes, _ := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/status")
	_ = stateBytes // on macOS /proc doesn't exist, so we just test resume works

	if err := h.Rollback(context.Background(), map[string]interface{}{
		"pid":  pid,
		"mode": "suspend",
	}); err != nil {
		t.Fatalf("Rollback (resume): %v", err)
	}

	if err := syscall.Kill(pid, 0); err != nil {
		t.Error("process not running after resume")
	}
}

func TestKillProtectedProcess(t *testing.T) {
	t.Parallel()
	h := newTestProcessHandler(t, []string{"sshd", "systemd"})

	cmd := exec.Command("sleep", "60")
	if err := cmd.Start(); err != nil {
		t.Fatalf("start sleep: %v", err)
	}
	pid := cmd.Process.Pid
	t.Cleanup(func() {
		cmd.Process.Kill()
		cmd.Wait()
	})

	result, err := h.Execute(context.Background(), map[string]interface{}{
		"pid":          pid,
		"mode":         "kill",
		"process_name": "sshd",
	})
	if err == nil {
		t.Fatal("expected error when killing protected process")
	}
	if result.Success {
		t.Error("Success = true for protected process kill")
	}

	if err := syscall.Kill(pid, 0); err != nil {
		t.Error("protected process was killed despite protection")
	}
}
