//go:build !cgo

package ml

import (
	"fmt"
	"sync"
)

// InitRuntime is a no-op when cgo is disabled. ONNX Runtime requires cgo.
func InitRuntime(numThreads int, useGPU bool, gpuDeviceID int) error {
	return fmt.Errorf("onnx: ONNX Runtime requires CGO_ENABLED=1")
}

// ShutdownRuntime is a no-op when cgo is disabled.
func ShutdownRuntime() error { return nil }

// ONNXSession is a stub when cgo is disabled.
type ONNXSession struct {
	mu sync.RWMutex
}

// NewONNXSession returns an error when cgo is disabled.
func NewONNXSession(modelPath string) (*ONNXSession, error) {
	return nil, fmt.Errorf("onnx: ONNX Runtime requires CGO_ENABLED=1")
}

// Predict returns an error when cgo is disabled.
func (s *ONNXSession) Predict(input []float32) ([]float32, error) {
	return nil, fmt.Errorf("onnx: session unavailable without cgo")
}

// InputShape returns nil when cgo is disabled.
func (s *ONNXSession) InputShape() []int64 { return nil }

// OutputShape returns nil when cgo is disabled.
func (s *ONNXSession) OutputShape() []int64 { return nil }

// Close is a no-op when cgo is disabled.
func (s *ONNXSession) Close() {}
