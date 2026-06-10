package detection

import (
	"testing"
	"time"

	"github.com/razatechofficial/edr/internal/schema"
	"github.com/razatechofficial/edr/pkg/events"
	"go.uber.org/zap"
)

func newTestRATDetector(t *testing.T) (*RATDetector, *Correlator) {
	t.Helper()
	logger, _ := zap.NewDevelopment()
	d := NewRATDetector(logger)
	c := NewCorrelator(logger)
	t.Cleanup(func() { c.Stop() })
	return d, c
}

func TestRATBeaconDetection(t *testing.T) {
	t.Parallel()
	d, c := newTestRATDetector(t)
	const pid = 1001
	now := time.Now()

	var alerts []*events.Alert
	for i := 0; i < 8; i++ {
		ev := &schema.NetworkEvent{
			BaseEvent: schema.BaseEvent{
				EventType: schema.EventNetwork,
				Timestamp: now.Add(time.Duration(i) * 5 * time.Millisecond),
			},
			PID:    pid,
			DestIP: "203.0.113.50",
			DestPt: 443,
		}
		result := d.Analyze(ev, c)
		if len(result) > 0 {
			alerts = result
		}
	}

	if len(alerts) == 0 {
		t.Fatal("expected beacon detection alert for regular-interval connections")
	}
	found := false
	for _, a := range alerts {
		if a.RuleID == "RAT-001" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected RAT-001 beacon alert")
	}
}

func TestRATRandomIntervals(t *testing.T) {
	t.Parallel()
	d, c := newTestRATDetector(t)
	const pid = 1002

	delays := []time.Duration{
		2 * time.Millisecond,
		50 * time.Millisecond,
		5 * time.Millisecond,
		80 * time.Millisecond,
		1 * time.Millisecond,
		60 * time.Millisecond,
		10 * time.Millisecond,
	}

	now := time.Now()
	for _, delay := range delays {
		ev := &schema.NetworkEvent{
			BaseEvent: schema.BaseEvent{
				EventType: schema.EventNetwork,
				Timestamp: now,
			},
			PID:    pid,
			DestIP: "198.51.100.10",
			DestPt: 8080,
		}
		now = now.Add(delay)
		alerts := d.Analyze(ev, c)
		for _, a := range alerts {
			if a.RuleID == "RAT-001" {
				t.Error("false positive: beacon alert for irregular intervals")
			}
		}
	}
}

func TestRATDGADetection(t *testing.T) {
	t.Parallel()
	d, c := newTestRATDetector(t)
	const pid = 1003

	dgaDomains := []string{
		"xkjhf7qwerty9z.com",
		"ahjksd8f7hgqwz.net",
		"zxcvbnm1234qwert.org",
	}

	var gotDGA bool
	for _, domain := range dgaDomains {
		ev := &schema.NetworkEvent{
			BaseEvent: schema.BaseEvent{EventType: schema.EventNetwork},
			PID:       pid,
			DestIP:    "10.0.0.1",
			DestPt:    53,
			Domain:    domain,
		}
		alerts := d.Analyze(ev, c)
		for _, a := range alerts {
			if a.RuleID == "RAT-002" {
				gotDGA = true
			}
		}
	}
	if !gotDGA {
		t.Error("expected DGA domain detection alert")
	}
}
