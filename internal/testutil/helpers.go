package testutil

import (
	"os"
	"testing"
	"time"

	"github.com/razatechofficial/edr/internal/kernel"
	"github.com/razatechofficial/edr/pkg/events"
)

// MustCreateTempFile creates a temporary file with the given content.
func MustCreateTempFile(t *testing.T, dir, pattern, content string) string {
	t.Helper()
	if dir == "" {
		dir = t.TempDir()
	}
	f, err := os.CreateTemp(dir, pattern)
	if err != nil {
		t.Fatalf("create temp file: %v", err)
	}
	if _, err := f.WriteString(content); err != nil {
		f.Close()
		t.Fatalf("write temp file: %v", err)
	}
	name := f.Name()
	if err := f.Close(); err != nil {
		t.Fatalf("close temp file: %v", err)
	}
	return name
}

func MakeProcessExecEvent(pid, ppid uint32, name, path, cmdline string) *events.ProcessExecEvent {
	return &events.ProcessExecEvent{
		Timestamp:   time.Now().UTC(),
		PID:         pid,
		PPID:        ppid,
		ProcessName: name,
		ProcessPath: path,
		CommandLine: cmdline,
	}
}

func MakeFileWriteEvent(pid uint32, path string, bytesWritten uint64, entropy float64) *events.FileWriteEvent {
	return &events.FileWriteEvent{
		Timestamp:    time.Now().UTC(),
		PID:          pid,
		Path:         path,
		BytesWritten: bytesWritten,
		Entropy:      entropy,
	}
}

func MakeNetworkConnectEvent(pid uint32, dstAddr string, dstPort uint16, protocol string) *events.NetworkConnectEvent {
	return &events.NetworkConnectEvent{
		Timestamp: time.Now().UTC(),
		PID:       pid,
		DstAddr:   dstAddr,
		DstPort:   dstPort,
		Protocol:  protocol,
	}
}

func MakeAlert(severity events.Severity, title, ruleID string) *events.Alert {
	return &events.Alert{
		ID:        "test-" + ruleID,
		RuleID:    ruleID,
		RuleName:  title,
		Severity:  severity,
		Title:     title,
		Timestamp: time.Now().UTC(),
	}
}

// WaitFor polls a condition function until it returns true or timeout expires.
func WaitFor(t *testing.T, timeout time.Duration, condition func() bool, msg string) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	interval := 10 * time.Millisecond
	for time.Now().Before(deadline) {
		if condition() {
			return
		}
		time.Sleep(interval)
		if interval < 200*time.Millisecond {
			interval *= 2
		}
	}
	t.Fatalf("WaitFor timed out after %v: %s", timeout, msg)
}

// NewTestRingBuffer creates a small ring buffer for testing.
func NewTestRingBuffer(size int) *kernel.RingBuffer {
	if size <= 0 {
		size = 4096
	}
	return kernel.NewRingBuffer(size)
}
