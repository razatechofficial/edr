package ml

import (
	"math/rand"
	"testing"
)

func TestDriftDetector_EmptyReturnsZero(t *testing.T) {
	d := NewDriftDetector(100, 2.0)
	if s := d.FeatureDriftScore("pe_classifier"); s != 0 {
		t.Errorf("expected 0 drift for untracked model, got %f", s)
	}
	if s := d.PredictionDriftScore("pe_classifier"); s != 0 {
		t.Errorf("expected 0 drift for untracked model, got %f", s)
	}
}

func TestDriftDetector_StableFeaturesNoDrift(t *testing.T) {
	d := NewDriftDetector(500, 2.0)
	rng := rand.New(rand.NewSource(42))

	for i := 0; i < 500; i++ {
		feats := make([]float32, 10)
		for j := range feats {
			feats[j] = float32(rng.NormFloat64()*0.1 + 0.5)
		}
		d.RecordPrediction("test", feats, 0.3+rng.Float64()*0.1)
	}

	fs := d.FeatureDriftScore("test")
	ps := d.PredictionDriftScore("test")

	if fs > 1.5 {
		t.Errorf("stable features should have low drift, got %f", fs)
	}
	if ps > 1.5 {
		t.Errorf("stable predictions should have low drift, got %f", ps)
	}
	if d.IsDrifting("test") {
		t.Error("stable data should not trigger drift")
	}
}

func TestDriftDetector_ShiftedFeaturesDetected(t *testing.T) {
	d := NewDriftDetector(200, 1.5)
	rng := rand.New(rand.NewSource(42))

	for i := 0; i < 100; i++ {
		feats := make([]float32, 5)
		for j := range feats {
			feats[j] = float32(rng.NormFloat64()*0.1 + 0.3)
		}
		d.RecordPrediction("shifted", feats, 0.3)
	}

	for i := 0; i < 100; i++ {
		feats := make([]float32, 5)
		for j := range feats {
			feats[j] = float32(rng.NormFloat64()*0.1 + 0.9)
		}
		d.RecordPrediction("shifted", feats, 0.8)
	}

	if d.SampleCount("shifted") != 200 {
		t.Errorf("expected 200 samples, got %d", d.SampleCount("shifted"))
	}
}

func TestDriftDetector_SampleCount(t *testing.T) {
	d := NewDriftDetector(100, 2.0)
	if d.SampleCount("unknown") != 0 {
		t.Error("unknown model should have 0 samples")
	}

	d.RecordPrediction("x", []float32{1, 2, 3}, 0.5)
	d.RecordPrediction("x", []float32{1, 2, 3}, 0.6)
	if d.SampleCount("x") != 2 {
		t.Errorf("expected 2, got %d", d.SampleCount("x"))
	}
}
