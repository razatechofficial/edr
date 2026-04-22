//go:build windows

// BLOCKER: Production memory dumps need dbghelp!MiniDumpWriteDump with the right process
// handle and SeDebugPrivilege; a placeholder file is not sufficient for analysis.

package actions

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// MemoryDump is a placeholder on Windows; production would use MiniDumpWriteDump via syscall.
type MemoryDump struct {
	PID          uint32
	ForensicsDir string
	ProcName     string
}

// Execute creates a small marker; link dbghelp for full dumps in production.
func (m *MemoryDump) Execute(ctx context.Context) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("memory_dump panic: %v", r)
		}
	}()
	_ = ctx
	out := filepath.Join(m.ForensicsDir, fmt.Sprintf("%d_%s_%d.dmp", time.Now().Unix(), m.ProcName, m.PID))
	_ = os.MkdirAll(filepath.Dir(out), 0o700)
	return os.WriteFile(out, []byte("placeholder windows minidump; use MiniDumpWriteDump in production\n"), 0o600)
}
