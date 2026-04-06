package ml

import (
	"fmt"
	"sync"

	ort "github.com/yalue/onnxruntime_go"
)

var (
	runtimeOnce sync.Once
	runtimeErr  error
)

// InitRuntime initializes the ONNX Runtime globally. Must be called before
// creating any sessions. Safe for concurrent calls; only the first invocation
// takes effect.
func InitRuntime(numThreads int, useGPU bool, gpuDeviceID int) error {
	runtimeOnce.Do(func() {
		if err := ort.InitializeEnvironment(); err != nil {
			runtimeErr = fmt.Errorf("onnx: initialize environment: %w", err)
			return
		}
	})
	return runtimeErr
}

// ShutdownRuntime tears down the ONNX Runtime environment. Call once at
// program exit after all sessions have been closed.
func ShutdownRuntime() error {
	return ort.DestroyEnvironment()
}

// ONNXSession wraps a single ONNX model for inference.
type ONNXSession struct {
	session     *ort.AdvancedSession
	inputName   string
	outputName  string
	inputShape  ort.Shape
	outputShape ort.Shape
	inputTensor  *ort.Tensor[float32]
	outputTensor *ort.Tensor[float32]
	mu          sync.RWMutex
}

// NewONNXSession loads an ONNX model from disk, discovers its input/output
// metadata, and prepares pre-allocated tensors for inference.
func NewONNXSession(modelPath string) (*ONNXSession, error) {
	inputs, outputs, err := ort.GetInputOutputInfo(modelPath)
	if err != nil {
		return nil, fmt.Errorf("onnx: model info for %s: %w", modelPath, err)
	}
	if len(inputs) == 0 || len(outputs) == 0 {
		return nil, fmt.Errorf("onnx: model %s has no inputs or outputs", modelPath)
	}

	inShape := normalizeDynamic(inputs[0].Dimensions)
	outShape := normalizeDynamic(outputs[0].Dimensions)

	inTensor, err := ort.NewEmptyTensor[float32](inShape)
	if err != nil {
		return nil, fmt.Errorf("onnx: create input tensor: %w", err)
	}

	outTensor, err := ort.NewEmptyTensor[float32](outShape)
	if err != nil {
		_ = inTensor.Destroy()
		return nil, fmt.Errorf("onnx: create output tensor: %w", err)
	}

	session, err := ort.NewAdvancedSession(
		modelPath,
		[]string{inputs[0].Name},
		[]string{outputs[0].Name},
		[]ort.Value{inTensor},
		[]ort.Value{outTensor},
		nil,
	)
	if err != nil {
		_ = inTensor.Destroy()
		_ = outTensor.Destroy()
		return nil, fmt.Errorf("onnx: create session for %s: %w", modelPath, err)
	}

	return &ONNXSession{
		session:      session,
		inputName:    inputs[0].Name,
		outputName:   outputs[0].Name,
		inputShape:   inShape,
		outputShape:  outShape,
		inputTensor:  inTensor,
		outputTensor: outTensor,
	}, nil
}

// Predict runs inference on the provided input features and returns the model
// output. Concurrent calls are serialized to protect shared tensor buffers.
func (s *ONNXSession) Predict(input []float32) ([]float32, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.session == nil {
		return nil, fmt.Errorf("onnx: session is closed")
	}

	s.inputTensor.ZeroContents()
	data := s.inputTensor.GetData()
	copy(data, input)

	if err := s.session.Run(); err != nil {
		return nil, fmt.Errorf("onnx: inference: %w", err)
	}

	out := s.outputTensor.GetData()
	result := make([]float32, len(out))
	copy(result, out)
	return result, nil
}

// InputShape returns the model's expected input tensor dimensions.
func (s *ONNXSession) InputShape() []int64 { return []int64(s.inputShape) }

// OutputShape returns the model's output tensor dimensions.
func (s *ONNXSession) OutputShape() []int64 { return []int64(s.outputShape) }

// Close releases the ONNX session and associated tensors.
func (s *ONNXSession) Close() {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.session != nil {
		_ = s.session.Destroy()
		s.session = nil
	}
	if s.inputTensor != nil {
		_ = s.inputTensor.Destroy()
		s.inputTensor = nil
	}
	if s.outputTensor != nil {
		_ = s.outputTensor.Destroy()
		s.outputTensor = nil
	}
}

// normalizeDynamic replaces dynamic dimensions (≤0) with 1 so that tensors
// can be pre-allocated with a concrete shape.
func normalizeDynamic(shape ort.Shape) ort.Shape {
	out := make(ort.Shape, len(shape))
	copy(out, shape)
	for i, d := range out {
		if d <= 0 {
			out[i] = 1
		}
	}
	return out
}
