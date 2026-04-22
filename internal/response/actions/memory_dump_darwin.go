//go:build darwin

// BLOCKER: Real memory capture needs task_for_pid, exception state, and proper entitlements;
// the implementation below is intentionally a marker until those are granted in the distribution.

package actions

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// MemoryDump creates a placeholder dump (full task access requires entitlements).
type MemoryDump struct {
	PID          uint32
	ForensicsDir string
	ProcName     string
}

// Execute creates a small marker file; full vm_read requires elevated rights.
func (m *MemoryDump) Execute(ctx context.Context) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("memory_dump panic: %v", r)
		}
	}()
	out := filepath.Join(m.ForensicsDir, fmt.Sprintf("%d_%s_%d.dmp", time.Now().Unix(), m.ProcName, m.PID))
	_ = os.MkdirAll(filepath.Dir(out), 0o700)
	return os.WriteFile(out, []byte("placeholder darwin memory dump; use task_for_pid+vm_read with entitlements for full content\n"), 0o600)
}
