package ml

import (
	"math"
	"sync"
)

// DriftDetector tracks rolling statistics on model input/output distributions
// to detect feature drift and prediction drift.
type DriftDetector struct {
	mu          sync.Mutex
	windowSize  int
	models      map[string]*modelDrift
	driftThresh float64
}

type modelDrift struct {
	featureStats []rollingStat
	scoreStats   rollingStat
	sampleCount  int
}

type rollingStat struct {
	values []float64
	pos    int
	full   bool
}

func newRollingStat(size int) rollingStat {
	return rollingStat{values: make([]float64, size)}
}

func (rs *rollingStat) push(v float64) {
	rs.values[rs.pos] = v
	rs.pos = (rs.pos + 1) % len(rs.values)
	if rs.pos == 0 {
		rs.full = true
	}
}

func (rs *rollingStat) count() int {
	if rs.full {
		return len(rs.values)
	}
	return rs.pos
}

func (rs *rollingStat) mean() float64 {
	n := rs.count()
	if n == 0 {
		return 0
	}
	var sum float64
	for i := 0; i < n; i++ {
		sum += rs.values[i]
	}
	return sum / float64(n)
}

func (rs *rollingStat) variance() float64 {
	n := rs.count()
	if n < 2 {
		return 0
	}
	m := rs.mean()
	var sumSq float64
	for i := 0; i < n; i++ {
		d := rs.values[i] - m
		sumSq += d * d
	}
	return sumSq / float64(n-1)
}

// NewDriftDetector creates a detector tracking rolling windows of the given
// size. driftThreshold is the score above which drift is considered significant.
func NewDriftDetector(windowSize int, driftThreshold float64) *DriftDetector {
	if windowSize <= 0 {
		windowSize = 1000
	}
	if driftThreshold <= 0 {
		driftThreshold = 2.0 // 2 standard deviations
	}
	return &DriftDetector{
		windowSize:  windowSize,
		models:      make(map[string]*modelDrift),
		driftThresh: driftThreshold,
	}
}

// RecordPrediction records a model prediction for drift tracking.
func (d *DriftDetector) RecordPrediction(modelName string, features []float32, score float64) {
	d.mu.Lock()
	defer d.mu.Unlock()

	md, ok := d.models[modelName]
	if !ok {
		md = &modelDrift{
			featureStats: make([]rollingStat, len(features)),
			scoreStats:   newRollingStat(d.windowSize),
		}
		for i := range md.featureStats {
			md.featureStats[i] = newRollingStat(d.windowSize)
		}
		d.models[modelName] = md
	}

	for i, f := range features {
		if i < len(md.featureStats) {
			md.featureStats[i].push(float64(f))
		}
	}
	md.scoreStats.push(score)
	md.sampleCount++
}

// FeatureDriftScore computes the average z-score deviation across all feature
// dimensions for the given model. Higher values indicate more drift.
func (d *DriftDetector) FeatureDriftScore(modelName string) float64 {
	d.mu.Lock()
	defer d.mu.Unlock()

	md, ok := d.models[modelName]
	if !ok || md.sampleCount < 100 {
		return 0
	}

	var totalZ float64
	var count int
	for _, fs := range md.featureStats {
		if fs.count() < 10 {
			continue
		}
		v := fs.variance()
		if v < 1e-10 {
			continue
		}
		halfN := fs.count() / 2
		var firstMean, secondMean float64
		for i := 0; i < halfN; i++ {
			firstMean += fs.values[i]
		}
		firstMean /= float64(halfN)
		for i := halfN; i < fs.count(); i++ {
			secondMean += fs.values[i]
		}
		secondMean /= float64(fs.count() - halfN)

		z := math.Abs(secondMean-firstMean) / math.Sqrt(v)
		totalZ += z
		count++
	}

	if count == 0 {
		return 0
	}
	return totalZ / float64(count)
}

// PredictionDriftScore measures how much the score distribution has shifted.
func (d *DriftDetector) PredictionDriftScore(modelName string) float64 {
	d.mu.Lock()
	defer d.mu.Unlock()

	md, ok := d.models[modelName]
	if !ok || md.scoreStats.count() < 100 {
		return 0
	}

	v := md.scoreStats.variance()
	if v < 1e-10 {
		return 0
	}

	halfN := md.scoreStats.count() / 2
	var firstMean, secondMean float64
	for i := 0; i < halfN; i++ {
		firstMean += md.scoreStats.values[i]
	}
	firstMean /= float64(halfN)
	for i := halfN; i < md.scoreStats.count(); i++ {
		secondMean += md.scoreStats.values[i]
	}
	secondMean /= float64(md.scoreStats.count() - halfN)

	return math.Abs(secondMean-firstMean) / math.Sqrt(v)
}

// IsDrifting returns true if either feature or prediction drift exceeds threshold.
func (d *DriftDetector) IsDrifting(modelName string) bool {
	return d.FeatureDriftScore(modelName) > d.driftThresh ||
		d.PredictionDriftScore(modelName) > d.driftThresh
}

// SampleCount returns how many predictions have been recorded for a model.
func (d *DriftDetector) SampleCount(modelName string) int {
	d.mu.Lock()
	defer d.mu.Unlock()
	if md, ok := d.models[modelName]; ok {
		return md.sampleCount
	}
	return 0
}
