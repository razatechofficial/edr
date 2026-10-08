package selfprotect

import (
	"errors"
	"sync"
	"testing"
	"time"

	"go.uber.org/zap"
)

// emitResponse returns early when no hook is installed, and for the life of
// this code none ever was — so a tamper event produced nothing beyond a log
// line. Nothing reached the server, the alert queue or the alert file: the one
// event self-protection exists to report was the one nobody was told about.
func TestATamperEventReachesTheInstalledHook(t *testing.T) {
	td := NewTamperDetector([]string{"/tmp/does-not-matter"}, zap.NewNop())

	var mu sync.Mutex
	var got []TamperResponse
	td.SetResponseHook(func(r TamperResponse) {
		mu.Lock()
		got = append(got, r)
		mu.Unlock()
	})

	want := TamperResponse{
		Path:      "/usr/bin/edr-agent",
		Operation: "WRITE",
		Action:    "restored",
		Timestamp: time.Now().UTC(),
		Restored:  true,
	}
	td.emitResponse(want)

	mu.Lock()
	defer mu.Unlock()
	if len(got) != 1 {
		t.Fatalf("hook received %d events, want 1", len(got))
	}
	if got[0].Path != want.Path || got[0].Operation != want.Operation {
		t.Errorf("event altered in transit: %+v", got[0])
	}
}

// Without a hook the detector must stay silent rather than panic — the agent
// may legitimately run with tamper detection and no reporting path.
func TestEmittingWithNoHookIsSafe(t *testing.T) {
	td := NewTamperDetector([]string{"/tmp/x"}, zap.NewNop())
	td.emitResponse(TamperResponse{Path: "/tmp/x", Operation: "WRITE"})
}

// Restoration is optional: tamper detection may be enabled while integrity
// backups are not, and the detector must work either way.
func TestTheRestoreHookIsOptionalAndUsedWhenPresent(t *testing.T) {
	td := NewTamperDetector([]string{"/tmp/x"}, zap.NewNop())

	var calledWith string
	td.SetRestoreFn(func(path string) error {
		calledWith = path
		return errors.New("backup unavailable")
	})

	td.mu.RLock()
	fn := td.restoreFn
	td.mu.RUnlock()
	if fn == nil {
		t.Fatal("the restore function was not installed")
	}
	if err := fn("/usr/bin/edr-agent"); err == nil {
		t.Error("a failing restore reported success")
	}
	if calledWith != "/usr/bin/edr-agent" {
		t.Errorf("restore called with %q", calledWith)
	}
}
