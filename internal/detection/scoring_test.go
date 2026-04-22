package detection

import (
	"testing"
	"time"

	"github.com/razatechofficial/edr/internal/schema"
)

func TestScoringEngineTechniqueScore(t *testing.T) {
	s := NewScoringEngine()
	d := &Detection{
		TechniqueID: "T1055",
		Severity:    P0,
		Confidence:  0.9,
		Timestamp:   time.Now().UTC(),
		Event: &EventPayload{Process: &schema.ProcessEvent{
			ProcessName: "unknown.exe",
		}},
	}
	s.Score(d)
	if d.Confidence < 0.5 {
		t.Fatalf("expected high confidence score, got %.2f", d.Confidence)
	}
}

func TestScoringKnownGoodRaisesFP(t *testing.T) {
	s := NewScoringEngine()
	d := &Detection{
		TechniqueID:        "T1055",
		Severity:           P0,
		Confidence:         0.9,
		FalsePositiveScore: 0.05,
		Timestamp:          time.Now().UTC(),
		Event: &EventPayload{Process: &schema.ProcessEvent{
			ProcessName: "chrome.exe",
			ProcessPath: `C:\Program Files\Google\Chrome\Application\chrome.exe`,
		}},
	}
	beforeC := d.Confidence
	beforeFP := d.FalsePositiveScore
	s.Score(d)
	if d.FalsePositiveScore <= beforeFP {
		t.Fatalf("expected false positive score to increase for known-good, got %v", d.FalsePositiveScore)
	}
	if d.Confidence >= beforeC {
		t.Fatalf("expected confidence to drop for known-good, before=%.2f after=%.2f", beforeC, d.Confidence)
	}
}
