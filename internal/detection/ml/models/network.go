package models

import (
	"fmt"

	"github.com/razatechofficial/edr/internal/detection/ml"
)

// NetworkAnomalyDetector wraps the network anomaly detection ONNX model.
type NetworkAnomalyDetector struct {
	session   *ml.ONNXSession
	threshold float32
}

// NewNetworkAnomalyDetector loads the network anomaly model from modelPath.
func NewNetworkAnomalyDetector(modelPath string, threshold float32) (*NetworkAnomalyDetector, error) {
	s, err := ml.NewONNXSession(modelPath)
	if err != nil {
		return nil, fmt.Errorf("network_anomaly: %w", err)
	}
	if threshold <= 0 || threshold > 1 {
		threshold = 0.5
	}
	return &NetworkAnomalyDetector{session: s, threshold: threshold}, nil
}

// Score evaluates the connection feature vector and returns an anomaly score
// and a binary verdict.
func (d *NetworkAnomalyDetector) Score(features []float32) (score float32, anomalous bool, err error) {
	output, err := d.session.Predict(features)
	if err != nil {
		return 0, false, fmt.Errorf("network_anomaly: %w", err)
	}
	if len(output) < 1 {
		return 0, false, fmt.Errorf("network_anomaly: empty output")
	}
	score = output[0]
	return score, score >= d.threshold, nil
}

// Close releases the underlying ONNX session.
func (d *NetworkAnomalyDetector) Close() { d.session.Close() }
