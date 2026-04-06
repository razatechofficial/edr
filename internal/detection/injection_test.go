package detection

import (
	"testing"

	"github.com/razatechofficial/edr/internal/schema"
	"go.uber.org/zap"
)

func newTestInjectionDetector(t *testing.T) (*InjectionDetector, *Correlator) {
	t.Helper()
	logger, _ := zap.NewDevelopment()
	d := NewInjectionDetector(logger)
	c := NewCorrelator(logger)
	t.Cleanup(func() { c.Stop() })
	return d, c
}

func TestInjectionProcessHollowing(t *testing.T) {
	t.Parallel()
	d, c := newTestInjectionDetector(t)
	const pid = 2001

	ev := &schema.ProcessEvent{
		BaseEvent:   schema.BaseEvent{EventType: schema.EventProcess},
		PID:         pid,
		ProcessName: "svchost.exe",
		ProcessPath: "C:\\Users\\attacker\\malware\\svchost.exe",
	}

	alerts := d.Analyze(ev, c)
	if len(alerts) == 0 {
		t.Fatal("expected hollowing alert for svchost.exe from non-standard path")
	}

	found := false
	for _, a := range alerts {
		if a.RuleID == "INJECT-003" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected INJECT-003 process hollowing alert")
	}
}

func TestInjectionNormalProcessStart(t *testing.T) {
	t.Parallel()
	d, c := newTestInjectionDetector(t)

	ev := &schema.ProcessEvent{
		BaseEvent:   schema.BaseEvent{EventType: schema.EventProcess},
		PID:         2002,
		ProcessName: "notepad.exe",
		ProcessPath: "C:\\Windows\\System32\\notepad.exe",
		CommandLine: "notepad.exe readme.txt",
	}

	alerts := d.Analyze(ev, c)
	if len(alerts) != 0 {
		t.Errorf("got %d alerts for normal process start, want 0", len(alerts))
	}
}
