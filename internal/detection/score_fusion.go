package detection

import (
	"fmt"
	"math"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/razatechofficial/edr/pkg/events"
)

// LayerVerdict captures a single detection layer's scoring output.
type LayerVerdict struct {
	LayerName   string
	Score       float64
	Confidence  float64
	TechniqueID string
	RuleID      string
	Severity    events.Severity
}

// ScoreFusionConfig holds per-layer weight configuration.
type ScoreFusionConfig struct {
	Weights              map[string]float64
	CorroborationBonus   float64
	CorroborationMinN    int
	FPCalibrationRatios  map[string]float64
}

// DefaultScoreFusionConfig returns industry-standard layer weights.
func DefaultScoreFusionConfig() ScoreFusionConfig {
	return ScoreFusionConfig{
		Weights: map[string]float64{
			"ioc":        0.95,
			"yara":       0.90,
			"sigma":      0.80,
			"cel":        0.80,
			"behavioral": 0.85,
			"ml":         0.88,
			"llm":        0.70,
		},
		CorroborationBonus: 0.15,
		CorroborationMinN:  2,
		FPCalibrationRatios: map[string]float64{
			"ioc":        0.02,
			"yara":       0.05,
			"sigma":      0.08,
			"behavioral": 0.10,
			"ml":         0.06,
		},
	}
}

// ScoreFusionEngine implements weighted voting and corroboration across
// detection layers.
type ScoreFusionEngine struct {
	cfg ScoreFusionConfig

	mu           sync.RWMutex
	tpCounts     map[string]uint64
	fpCounts     map[string]uint64
	assetValues  map[string]float64
	knownGood    map[string]struct{}
	baseScores   map[string]float64
}

// NewScoreFusionEngine constructs a fusion engine with the given config.
func NewScoreFusionEngine(cfg ScoreFusionConfig) *ScoreFusionEngine {
	return &ScoreFusionEngine{
		cfg:         cfg,
		tpCounts:    make(map[string]uint64),
		fpCounts:    make(map[string]uint64),
		assetValues: make(map[string]float64),
		knownGood:   defaultKnownGood(),
		baseScores:  defaultTechniqueScores(),
	}
}

// Fuse takes the raw alerts produced by individual layers and returns a
// deduplicated, scored set including a composite alert when multiple layers
// corroborate. It replaces the old mergeScores() function.
func (f *ScoreFusionEngine) Fuse(alerts []*events.Alert) []*events.Alert {
	if len(alerts) == 0 {
		return nil
	}

	verdicts := f.extractVerdicts(alerts)

	// Score each individual alert using its layer weight.
	for i, a := range alerts {
		if i < len(verdicts) {
			f.scoreAlert(a, verdicts[i])
		}
	}

	// If multiple layers agree, produce a composite corroborated alert.
	if len(verdicts) >= f.cfg.CorroborationMinN {
		composite := f.buildCompositeAlert(alerts, verdicts)
		if composite != nil {
			alerts = append(alerts, composite)
		}
	}

	return alerts
}

// FuseWithVerdicts accepts explicit layer verdicts (for the new timeout-bounded
// fan-out pattern where layers return structured results).
func (f *ScoreFusionEngine) FuseWithVerdicts(alerts []*events.Alert, verdicts []LayerVerdict) []*events.Alert {
	if len(alerts) == 0 {
		return nil
	}

	for i, a := range alerts {
		if i < len(verdicts) {
			f.scoreAlert(a, verdicts[i])
		}
	}

	if len(verdicts) >= f.cfg.CorroborationMinN {
		composite := f.buildCompositeAlert(alerts, verdicts)
		if composite != nil {
			alerts = append(alerts, composite)
		}
	}

	return alerts
}

func (f *ScoreFusionEngine) extractVerdicts(alerts []*events.Alert) []LayerVerdict {
	verdicts := make([]LayerVerdict, 0, len(alerts))
	for _, a := range alerts {
		v := LayerVerdict{
			LayerName:   inferLayer(a),
			Score:       severityToScore(a.Severity),
			Confidence:  0.7,
			TechniqueID: extractTechniqueID(a),
			RuleID:      a.RuleID,
			Severity:    a.Severity,
		}
		verdicts = append(verdicts, v)
	}
	return verdicts
}

func (f *ScoreFusionEngine) scoreAlert(a *events.Alert, v LayerVerdict) {
	weight := f.layerWeight(v.LayerName)
	fpRatio := f.fpCalibration(v.LayerName)
	confidence := v.Confidence * (1.0 - fpRatio)

	finalScore := weight * v.Score * confidence
	finalScore = clamp01(finalScore)

	a.Severity = scoreToSeverity(finalScore)
}

func (f *ScoreFusionEngine) buildCompositeAlert(alerts []*events.Alert, verdicts []LayerVerdict) *events.Alert {
	if len(alerts) < 2 {
		return nil
	}

	// Weighted fusion score
	var weightedSum, weightSum float64
	for _, v := range verdicts {
		w := f.layerWeight(v.LayerName)
		fpRatio := f.fpCalibration(v.LayerName)
		confidence := v.Confidence * (1.0 - fpRatio)
		weightedSum += w * v.Score * confidence
		weightSum += w
	}
	if weightSum == 0 {
		weightSum = 1
	}
	fusedScore := weightedSum / weightSum

	// Apply corroboration bonus
	if len(verdicts) >= f.cfg.CorroborationMinN {
		fusedScore = math.Min(fusedScore+f.cfg.CorroborationBonus, 1.0)
	}

	severity := scoreToSeverity(fusedScore)

	var allMITRE []events.MITREAttack
	tagSet := make(map[string]struct{})
	layerNames := make([]string, 0, len(verdicts))
	for _, a := range alerts {
		allMITRE = append(allMITRE, a.MITRE...)
		for _, t := range a.Tags {
			tagSet[t] = struct{}{}
		}
	}
	for _, v := range verdicts {
		layerNames = append(layerNames, v.LayerName)
	}

	tags := make([]string, 0, len(tagSet)+2)
	for t := range tagSet {
		tags = append(tags, t)
	}
	tags = append(tags, "composite", "corroborated")

	fp := alerts[0].FilePath
	h256 := alerts[0].FileSHA256
	for _, a := range alerts[1:] {
		if fp == "" && a.FilePath != "" {
			fp = a.FilePath
		}
		if h256 == "" && a.FileSHA256 != "" {
			h256 = a.FileSHA256
		}
	}

	return &events.Alert{
		ID:          uuid.New().String(),
		RuleID:      "score-fusion",
		RuleName:    "Score Fusion Engine",
		Severity:    severity,
		Title:       fmt.Sprintf("Corroborated: %d layers triggered", len(verdicts)),
		Description: fmt.Sprintf("Layers: %v | Fused score: %.2f", layerNames, fusedScore),
		Timestamp:   time.Now().UTC(),
		MITRE:       deduplicateMITRE(allMITRE),
		Tags:        tags,
		RawEvent:    alerts[0].RawEvent,
		FilePath:    fp,
		FileSHA256:  h256,
	}
}

// RecordTruePositive updates calibration counters for a given layer.
func (f *ScoreFusionEngine) RecordTruePositive(layer string) {
	f.mu.Lock()
	f.tpCounts[layer]++
	f.mu.Unlock()
}

// RecordFalsePositive updates calibration counters for a given layer.
func (f *ScoreFusionEngine) RecordFalsePositive(layer string) {
	f.mu.Lock()
	f.fpCounts[layer]++
	f.mu.Unlock()
}

func (f *ScoreFusionEngine) layerWeight(layer string) float64 {
	w, ok := f.cfg.Weights[strings.ToLower(layer)]
	if !ok {
		return 0.75
	}
	return w
}

func (f *ScoreFusionEngine) fpCalibration(layer string) float64 {
	f.mu.RLock()
	tp := f.tpCounts[layer]
	fp := f.fpCounts[layer]
	f.mu.RUnlock()

	total := tp + fp
	if total > 100 {
		return float64(fp) / float64(total)
	}
	// Not enough data; use configured baseline.
	r, ok := f.cfg.FPCalibrationRatios[strings.ToLower(layer)]
	if !ok {
		return 0.05
	}
	return r
}

func inferLayer(a *events.Alert) string {
	id := strings.ToLower(a.RuleID)
	switch {
	case strings.HasPrefix(id, "ioc"):
		return "ioc"
	case strings.HasPrefix(id, "yara"):
		return "yara"
	case strings.HasPrefix(id, "sigma"):
		return "sigma"
	case strings.HasPrefix(id, "cel"):
		return "cel"
	case strings.HasPrefix(id, "ml") || strings.HasPrefix(id, "pe_") || strings.HasPrefix(id, "behavior_") || strings.HasPrefix(id, "network_"):
		return "ml"
	case strings.HasPrefix(id, "llm"):
		return "llm"
	default:
		for _, t := range a.Tags {
			switch strings.ToLower(t) {
			case "ioc":
				return "ioc"
			case "yara":
				return "yara"
			case "sigma":
				return "sigma"
			case "behavioral":
				return "behavioral"
			case "ml":
				return "ml"
			}
		}
		return "behavioral"
	}
}

func extractTechniqueID(a *events.Alert) string {
	if len(a.MITRE) > 0 {
		return a.MITRE[0].TechniqueID
	}
	return ""
}

func severityToScore(s events.Severity) float64 {
	switch s {
	case events.SeverityCritical:
		return 1.0
	case events.SeverityHigh:
		return 0.8
	case events.SeverityMedium:
		return 0.6
	case events.SeverityLow:
		return 0.4
	default:
		return 0.2
	}
}

func scoreToSeverity(score float64) events.Severity {
	switch {
	case score >= 0.9:
		return events.SeverityCritical
	case score >= 0.7:
		return events.SeverityHigh
	case score >= 0.5:
		return events.SeverityMedium
	case score >= 0.3:
		return events.SeverityLow
	default:
		return events.SeverityInfo
	}
}
