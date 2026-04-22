//go:build linux

// BLOCKER: Reading /proc/<pid>/mem is restricted (ptrace, dumpable, or same user); a full
// forensics capture usually needs a coordinated kernel or crash dump path, not a blind read.

package actions

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// MemoryDump writes a best-effort memory image from /proc (debugging aid, not a full core).
type MemoryDump struct {
	PID          uint32
	ForensicsDir string
	ProcName     string
}

// Execute reads /proc/pid/mem where allowed (panic-safe).
func (m *MemoryDump) Execute(ctx context.Context) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("memory_dump panic: %v", r)
		}
	}()
	if m.PID == 0 {
		return fmt.Errorf("invalid pid")
	}
	_, err = os.Stat(fmt.Sprintf("/proc/%d", m.PID))
	if err != nil {
		return fmt.Errorf("process %d not found: %w", m.PID, err)
	}
	out := filepath.Join(m.ForensicsDir, fmt.Sprintf("%d_%s_%d.dmp", time.Now().Unix(), m.ProcName, m.PID))
	_ = os.MkdirAll(filepath.Dir(out), 0o700)
	mem, err := os.ReadFile(fmt.Sprintf("/proc/%d/mem", m.PID))
	if err != nil {
		// often permission denied; write placeholder
		return os.WriteFile(out+".txt", []byte("mem read denied or unsupported"), 0o600)
	}
	return os.WriteFile(out, mem, 0o600)
}
