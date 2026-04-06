package models

import (
	"fmt"

	"github.com/razatechofficial/edr/internal/detection/ml"
)

// BehaviorLSTM wraps the behavioral LSTM ONNX model for process-sequence
// anomaly detection.
type BehaviorLSTM struct {
	session   *ml.ONNXSession
	threshold float32
}

// NewBehaviorLSTM loads the behavioral LSTM model from modelPath.
func NewBehaviorLSTM(modelPath string, threshold float32) (*BehaviorLSTM, error) {
	s, err := ml.NewONNXSession(modelPath)
	if err != nil {
		return nil, fmt.Errorf("behavior_lstm: %w", err)
	}
	if threshold <= 0 || threshold > 1 {
		threshold = 0.5
	}
	return &BehaviorLSTM{session: s, threshold: threshold}, nil
}

// Score evaluates the behavorial feature vector and returns an anomaly score
// and a binary verdict.
func (m *BehaviorLSTM) Score(features []float32) (score float32, anomalous bool, err error) {
	output, err := m.session.Predict(features)
	if err != nil {
		return 0, false, fmt.Errorf("behavior_lstm: %w", err)
	}
	if len(output) < 1 {
		return 0, false, fmt.Errorf("behavior_lstm: empty output")
	}
	score = output[0]
	return score, score >= m.threshold, nil
}

// Close releases the underlying ONNX session.
func (m *BehaviorLSTM) Close() { m.session.Close() }
