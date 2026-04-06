package detection

import (
	"testing"

	"github.com/razatechofficial/edr/internal/schema"
	"go.uber.org/zap"
)

func newTestCredentialDetector(t *testing.T) (*CredentialDetector, *Correlator) {
	t.Helper()
	logger, _ := zap.NewDevelopment()
	d := NewCredentialDetector(logger)
	c := NewCorrelator(logger)
	t.Cleanup(func() { c.Stop() })
	return d, c
}

func TestCredentialLsassAccess(t *testing.T) {
	t.Parallel()
	d, c := newTestCredentialDetector(t)

	ev := &schema.FileEvent{
		BaseEvent: schema.BaseEvent{EventType: schema.EventFile},
		ActorPID:  3001,
		Path:      "C:\\Windows\\System32\\lsass.exe",
		Operation: "read",
	}

	alerts := d.Analyze(ev, c)
	if len(alerts) == 0 {
		t.Fatal("expected credential alert for lsass.exe access")
	}

	found := false
	for _, a := range alerts {
		if a.RuleID == "CRED-001" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected CRED-001 credential store alert")
	}
}

func TestCredentialNormalAccess(t *testing.T) {
	t.Parallel()
	d, c := newTestCredentialDetector(t)

	ev := &schema.FileEvent{
		BaseEvent: schema.BaseEvent{EventType: schema.EventFile},
		ActorPID:  3002,
		Path:      "/home/user/document.txt",
		Operation: "read",
	}

	alerts := d.Analyze(ev, c)
	if len(alerts) != 0 {
		t.Errorf("got %d alerts for normal file access, want 0", len(alerts))
	}
}
