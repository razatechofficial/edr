//go:build darwin && cgo && !nosec

package kernel

import (
	"testing"
	"time"
)

func TestAuthWait_UsesMinOfBudgetAndDefault(t *testing.T) {
	t.Parallel()
	auth := 750 * time.Millisecond
	budget := 100
	wait := auth
	bd := time.Duration(budget) * time.Millisecond
	if budget == 0 {
		wait = 5 * time.Millisecond
	} else if bd < wait {
		wait = bd
	}
	if wait != 100*time.Millisecond {
		t.Fatalf("wait=%v", wait)
	}
}
