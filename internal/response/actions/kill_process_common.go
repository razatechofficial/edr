package actions

import (
	"context"
	"fmt"
	"sort"
)

// KillProcessAction kills a process by PID, optionally killing children first (bottom-up).
type KillProcessAction struct {
	PID             uint32
	IncludeChildren bool
}

// Execute runs the kill with panic recovery. Verifies the PID still exists before sending signals.
func (a *KillProcessAction) Execute(ctx context.Context) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("kill_process panic: %v", r)
		}
	}()
	if a.PID == 0 {
		return fmt.Errorf("invalid pid 0")
	}
	if a.IncludeChildren {
		children, cErr := getChildPIDs(ctx, a.PID)
		if cErr == nil && len(children) > 0 {
			// Heuristic: kill higher PIDs first (approximate child ordering)
			sort.Slice(children, func(i, j int) bool { return children[i] > children[j] })
			for _, c := range children {
				_ = killOne(c)
			}
		}
	}
	return killOne(a.PID)
}
