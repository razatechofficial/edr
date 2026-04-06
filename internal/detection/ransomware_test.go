package detection

import (
	"fmt"
	"testing"
	"time"

	"github.com/razatechofficial/edr/internal/schema"
	"github.com/razatechofficial/edr/pkg/events"
	"go.uber.org/zap"
)

func newTestRansomwareDetector(t *testing.T) (*RansomwareDetector, *Correlator) {
	t.Helper()
	logger, _ := zap.NewDevelopment()
	d := NewRansomwareDetector(logger)
	c := NewCorrelator(logger)
	t.Cleanup(func() { c.Stop() })
	return d, c
}

func TestRansomwareHighEntropy(t *testing.T) {
	t.Parallel()
	d, c := newTestRansomwareDetector(t)
	const pid = 500

	d.Analyze(&schema.FileEvent{
		BaseEvent: schema.BaseEvent{EventType: schema.EventFile},
		ActorPID:  pid,
		Path:      "/tmp/docs/important.encrypted",
		Operation: "rename",
	}, c)

	d.Analyze(&schema.FileEvent{
		BaseEvent: schema.BaseEvent{EventType: schema.EventFile},
		ActorPID:  pid,
		Path:      "/tmp/docs/DECRYPT_README.txt",
		Operation: "create",
	}, c)

	alerts := d.Analyze(&schema.ProcessEvent{
		BaseEvent:   schema.BaseEvent{EventType: schema.EventProcess},
		PID:         pid,
		CommandLine: "vssadmin delete shadows /all /quiet",
	}, c)

	if len(alerts) == 0 {
		t.Fatal("expected alert for combined ransomware signals")
	}
	if alerts[0].Severity != events.SeverityCritical {
		t.Errorf("Severity = %q, want %q", alerts[0].Severity, events.SeverityCritical)
	}
}

func TestRansomwareMassFileOps(t *testing.T) {
	t.Parallel()
	d, c := newTestRansomwareDetector(t)
	const pid = 600

	now := time.Now()
	for i := 0; i < 55; i++ {
		ev := &schema.FileEvent{
			BaseEvent: schema.BaseEvent{EventType: schema.EventFile, Timestamp: now},
			ActorPID:  pid,
			Path:      fmt.Sprintf("/data/file%d.doc", i),
			Operation: "write",
		}
		c.AddEvent(ev)
	}

	d.Analyze(&schema.FileEvent{
		BaseEvent: schema.BaseEvent{EventType: schema.EventFile, Timestamp: now},
		ActorPID:  pid,
		Path:      "/data/document.encrypted",
		Operation: "rename",
	}, c)

	alerts := d.Analyze(&schema.FileEvent{
		BaseEvent: schema.BaseEvent{EventType: schema.EventFile, Timestamp: now},
		ActorPID:  pid,
		Path:      "/data/file56.doc",
		Operation: "write",
	}, c)

	if len(alerts) == 0 {
		t.Fatal("expected alert for mass file operations + extension change")
	}
}

func TestRansomwareShadowCopyDelete(t *testing.T) {
	t.Parallel()
	d, c := newTestRansomwareDetector(t)
	const pid = 700

	d.Analyze(&schema.FileEvent{
		BaseEvent: schema.BaseEvent{EventType: schema.EventFile},
		ActorPID:  pid,
		Path:      "/tmp/victim.encrypted",
		Operation: "rename",
	}, c)

	alerts := d.Analyze(&schema.ProcessEvent{
		BaseEvent:   schema.BaseEvent{EventType: schema.EventProcess},
		PID:         pid,
		CommandLine: "vssadmin delete shadows /all /quiet",
	}, c)

	if len(alerts) == 0 {
		t.Fatal("expected alert for shadow copy deletion + extension change")
	}
}

func TestRansomwareCombinedScore(t *testing.T) {
	t.Parallel()
	d, c := newTestRansomwareDetector(t)
	const pid = 800

	d.Analyze(&schema.FileEvent{
		BaseEvent: schema.BaseEvent{EventType: schema.EventFile},
		ActorPID:  pid,
		Path:      "/tmp/report.encrypted",
		Operation: "rename",
	}, c)

	d.Analyze(&schema.FileEvent{
		BaseEvent: schema.BaseEvent{EventType: schema.EventFile},
		ActorPID:  pid,
		Path:      "/tmp/HOW_TO_DECRYPT_README.txt",
		Operation: "create",
	}, c)

	alerts := d.Analyze(&schema.ProcessEvent{
		BaseEvent:   schema.BaseEvent{EventType: schema.EventProcess},
		PID:         pid,
		CommandLine: "vssadmin delete shadows /all /quiet",
	}, c)

	if len(alerts) == 0 {
		t.Fatal("expected critical alert for 3+ signals")
	}
	if alerts[0].Severity != events.SeverityCritical {
		t.Errorf("Severity = %q, want %q", alerts[0].Severity, events.SeverityCritical)
	}
}

func TestRansomwareNormalActivity(t *testing.T) {
	t.Parallel()
	d, c := newTestRansomwareDetector(t)

	alerts := d.Analyze(&schema.FileEvent{
		BaseEvent: schema.BaseEvent{EventType: schema.EventFile},
		ActorPID:  999,
		Path:      "/home/user/report.pdf",
		Operation: "write",
	}, c)
	if len(alerts) != 0 {
		t.Errorf("got %d alerts for normal file write, want 0", len(alerts))
	}

	alerts = d.Analyze(&schema.ProcessEvent{
		BaseEvent:   schema.BaseEvent{EventType: schema.EventProcess},
		PID:         999,
		CommandLine: "ls -la /tmp",
	}, c)
	if len(alerts) != 0 {
		t.Errorf("got %d alerts for normal process, want 0", len(alerts))
	}
}
