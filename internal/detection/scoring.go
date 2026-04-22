package detection

import (
	"strings"
	"time"
)

type ScoringEngine struct {
	assetValues map[string]float64
	baseScores  map[string]float64
	knownGood   map[string]struct{}
}

func NewScoringEngine() *ScoringEngine {
	return &ScoringEngine{
		assetValues: map[string]float64{},
		baseScores:  defaultTechniqueScores(),
		knownGood:   defaultKnownGood(),
	}
}

func (s *ScoringEngine) Score(d *Detection) {
	if d == nil {
		return
	}
	base := s.baseScores[d.TechniqueID]
	if base == 0 {
		base = severityBase(d.Severity)
	}
	conf := d.Confidence
	if conf <= 0 {
		conf = 0.7
	}
	assetMul := 1.0
	if h := strings.TrimSpace(extractHost(d.Event)); h != "" {
		if m, ok := s.assetValues[h]; ok && m > 0 {
			assetMul = m
		}
	}
	fp := d.FalsePositiveScore
	if fp <= 0 {
		fp = 0.05
	}
	recency := 1.0
	if !d.Timestamp.IsZero() {
		ageMins := time.Since(d.Timestamp).Minutes()
		if ageMins > 0 {
			recency = 1.0 / (1.0 + (ageMins / 60.0))
		}
	}
	score := base * conf * assetMul * (1.0 - fp) * recency
	d.Confidence = clamp01(score)
}

func defaultTechniqueScores() map[string]float64 {
	return map[string]float64{
		"T1055": 1.0,
		"T1003": 1.0,
		"T1486": 1.0,
		"T1059": 0.75,
		"T1547": 0.75,
		"T1021": 0.75,
		"T1078": 0.75,
		"T1562": 0.75,
	}
}

func defaultKnownGood() map[string]struct{} {
	return map[string]struct{}{
		"chrome.exe": {}, "firefox.exe": {}, "code.exe": {},
		"git.exe": {}, "node.exe": {}, "python.exe": {},
	}
}

func severityBase(s Severity) float64 {
	switch s {
	case P0:
		return 1.0
	case P1:
		return 0.75
	case P2:
		return 0.5
	default:
		return 0.25
	}
}

func clamp01(v float64) float64 {
	if v < 0 {
		return 0
	}
	if v > 1 {
		return 1
	}
	return v
}

func extractHost(event interface{}) string {
	m, ok := event.(map[string]interface{})
	if !ok {
		return ""
	}
	if v, ok := m["hostname"]; ok {
		return strings.TrimSpace(v.(string))
	}
	return ""
}
