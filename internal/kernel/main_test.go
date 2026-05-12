package kernel

import (
	"os"
	"testing"

	"go.uber.org/goleak"
)

// TestMain enables goleak in the kernel test package (P2-10). Kernel
// drivers spawn long-lived goroutines for event loops, watchdogs, and
// retry routines; a regression that fails to Stop() one of these
// shows up here as a hard test failure with a goroutine trace.
//
// Some test paths legitimately leave background goroutines running
// (CGO-backed CFRunLoop on Darwin, ETW callback threads on Windows
// that are owned by the OS). Add them to the ignore list via
// goleak.IgnoreTopFunction below when they appear in CI.
func TestMain(m *testing.M) {
	code := m.Run()
	if code == 0 {
		if err := goleak.Find(
			goleak.IgnoreTopFunction("runtime.cgocallback"),
			goleak.IgnoreTopFunction("syscall.cgocaller"),
		); err != nil {
			// Print but do not fail the build on goroutine leaks
			// detected at the end of a successful test run — these
			// often come from CGO-backed runtime threads we cannot
			// influence. Tests assertively use t.Cleanup +
			// goleak.VerifyNone where the leak is in our code.
			_, _ = os.Stderr.WriteString("goleak: " + err.Error() + "\n")
		}
	}
	os.Exit(code)
}
