package models

import (
	"fmt"

	"github.com/razatechofficial/edr/internal/detection/ml"
)

// PEClassifier wraps the PE malware classification ONNX model.
type PEClassifier struct {
	session   *ml.ONNXSession
	threshold float32
}

// NewPEClassifier loads the PE classifier model from modelPath. Scores at or
// above threshold are considered malicious.
func NewPEClassifier(modelPath string, threshold float32) (*PEClassifier, error) {
	s, err := ml.NewONNXSession(modelPath)
	if err != nil {
		return nil, fmt.Errorf("pe_classifier: %w", err)
	}
	if threshold <= 0 || threshold > 1 {
		threshold = 0.5
	}
	return &PEClassifier{session: s, threshold: threshold}, nil
}

// Classify runs the PE feature vector through the model and returns the
// maliciousness score and a binary verdict.
func (c *PEClassifier) Classify(features []float32) (score float32, malicious bool, err error) {
	output, err := c.session.Predict(features)
	if err != nil {
		return 0, false, fmt.Errorf("pe_classifier: %w", err)
	}
	if len(output) < 2 {
		return 0, false, fmt.Errorf("pe_classifier: expected >= 2 outputs, got %d", len(output))
	}
	score = output[1]
	return score, score >= c.threshold, nil
}

// Close releases the underlying ONNX session.
func (c *PEClassifier) Close() { c.session.Close() }
