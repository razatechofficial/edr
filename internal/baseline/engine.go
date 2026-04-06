package baseline

import (
	"math"
	"sync"
	"time"

	"go.uber.org/zap"
)

// Baseline holds the statistical model for a single observation series.
type Baseline struct {
	Count      int64     `json:"count"`
	Sum        float64   `json:"sum"`
	SumSquares float64   `json:"sum_squares"`
	Min        float64   `json:"min"`
	Max        float64   `json:"max"`
	FirstSeen  time.Time `json:"first_seen"`
	LastSeen   time.Time `json:"last_seen"`
}

// Mean returns the arithmetic mean of observations.
func (b *Baseline) Mean() float64 {
	if b.Count == 0 {
		return 0
	}
	return b.Sum / float64(b.Count)
}

// StdDev returns the population standard deviation.
func (b *Baseline) StdDev() float64 {
	if b.Count < 2 {
		return 0
	}
	n := float64(b.Count)
	variance := (b.SumSquares / n) - (b.Mean() * b.Mean())
	if variance < 0 {
		variance = 0
	}
	return math.Sqrt(variance)
}

// BaselineEngine manages learning and anomaly detection across categorised
// observation series. During the learning period it accumulates statistics;
// after that it flags values that deviate beyond the configured threshold.
type BaselineEngine struct {
	mu            sync.RWMutex
	baselines     map[string]map[string]*Baseline // category -> key -> baseline
	learningDays  int
	deviationMult float64
	createdAt     time.Time
	logger        *zap.Logger
}

// NewBaselineEngine creates an engine with a learning period of learningDays.
// Observations during the learning period are recorded but never flagged.
func NewBaselineEngine(learningDays int, logger *zap.Logger) *BaselineEngine {
	return &BaselineEngine{
		baselines:     make(map[string]map[string]*Baseline),
		learningDays:  learningDays,
		deviationMult: 3.0,
		createdAt:     time.Now(),
		logger:        logger,
	}
}

// SetDeviationMultiplier overrides the default 3-sigma threshold.
func (e *BaselineEngine) SetDeviationMultiplier(m float64) {
	e.mu.Lock()
	e.deviationMult = m
	e.mu.Unlock()
}

// IsLearning reports whether the engine is still in its initial learning phase.
func (e *BaselineEngine) IsLearning() bool {
	return time.Since(e.createdAt) < time.Duration(e.learningDays)*24*time.Hour
}

// AddObservation records a new data-point for the given category and key.
func (e *BaselineEngine) AddObservation(category string, key string, value float64) {
	e.mu.Lock()
	defer e.mu.Unlock()

	cats, ok := e.baselines[category]
	if !ok {
		cats = make(map[string]*Baseline)
		e.baselines[category] = cats
	}

	b, ok := cats[key]
	if !ok {
		b = &Baseline{
			Min:       value,
			Max:       value,
			FirstSeen: time.Now(),
		}
		cats[key] = b
	}

	b.Count++
	b.Sum += value
	b.SumSquares += value * value
	if value < b.Min {
		b.Min = value
	}
	if value > b.Max {
		b.Max = value
	}
	b.LastSeen = time.Now()
}

// IsAnomaly checks whether value deviates significantly from the established
// baseline. Returns (anomaly bool, deviation score). During the learning
// period it always returns false.
func (e *BaselineEngine) IsAnomaly(category string, key string, value float64) (bool, float64) {
	if e.IsLearning() {
		return false, 0
	}

	e.mu.RLock()
	defer e.mu.RUnlock()

	cats, ok := e.baselines[category]
	if !ok {
		return false, 0
	}
	b, ok := cats[key]
	if !ok {
		return true, 1.0
	}

	if b.Count < 10 {
		return false, 0
	}

	stddev := b.StdDev()
	if stddev == 0 {
		if value != b.Mean() {
			return true, 1.0
		}
		return false, 0
	}

	deviation := math.Abs(value-b.Mean()) / stddev
	return deviation > e.deviationMult, deviation
}

// Baselines returns a snapshot of all baselines for persistence.
func (e *BaselineEngine) Baselines() map[string]map[string]*Baseline {
	e.mu.RLock()
	defer e.mu.RUnlock()

	out := make(map[string]map[string]*Baseline, len(e.baselines))
	for cat, keys := range e.baselines {
		m := make(map[string]*Baseline, len(keys))
		for k, v := range keys {
			cp := *v
			m[k] = &cp
		}
		out[cat] = m
	}
	return out
}

// LoadBaselines replaces the engine's baselines with previously persisted data.
func (e *BaselineEngine) LoadBaselines(data map[string]map[string]*Baseline) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.baselines = data
}
