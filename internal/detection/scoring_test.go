package detection

import (
	"testing"
	"time"
)

func TestScoringEngineTechniqueScore(t *testing.T) {
	s := NewScoringEngine()
	d := &Detection{
		TechniqueID: "T1055",
		Severity:    P0,
		Confidence:  0.9,
		Timestamp:   time.Now().UTC(),
	}
	s.Score(d)
	if d.Confidence < 0.5 {
		t.Fatalf("expected high confidence score, got %.2f", d.Confidence)
	}
}
