package models

import (
	"fmt"

	"github.com/razatechofficial/edr/internal/detection/ml"
)

// RansomwareDetector wraps the ransomware-specific ONNX detection model.
type RansomwareDetector struct {
	session   *ml.ONNXSession
	threshold float32
}

// NewRansomwareDetector loads the ransomware model from modelPath.
func NewRansomwareDetector(modelPath string, threshold float32) (*RansomwareDetector, error) {
	s, err := ml.NewONNXSession(modelPath)
	if err != nil {
		return nil, fmt.Errorf("ransomware: %w", err)
	}
	if threshold <= 0 || threshold > 1 {
		threshold = 0.5
	}
	return &RansomwareDetector{session: s, threshold: threshold}, nil
}

// Score evaluates ransomware indicator features and returns a score and a
// binary verdict.
func (d *RansomwareDetector) Score(features []float32) (score float32, ransomware bool, err error) {
	output, err := d.session.Predict(features)
	if err != nil {
		return 0, false, fmt.Errorf("ransomware: %w", err)
	}
	if len(output) < 1 {
		return 0, false, fmt.Errorf("ransomware: empty output")
	}
	score = output[0]
	return score, score >= d.threshold, nil
}

// Close releases the underlying ONNX session.
func (d *RansomwareDetector) Close() { d.session.Close() }
