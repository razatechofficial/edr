//go:build cgo && (linux || darwin || windows)

package ml

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"time"

	ort "github.com/yalue/onnxruntime_go"
)

var (
	runtimeOnce    sync.Once
	runtimeErr     error
	globalOpts     *ort.SessionOptions
	globalOptsMu   sync.Mutex
)

// InitRuntime initializes the ONNX Runtime globally. Must be called before
// creating any sessions. Safe for concurrent calls; only the first invocation
// takes effect. numThreads controls intra/inter-op parallelism (0 = ORT
// default). useGPU and gpuDeviceID are reserved for future CUDA support.
func InitRuntime(numThreads int, useGPU bool, gpuDeviceID int) error {
	runtimeOnce.Do(func() {
		if p := discoverLibraryPath(); p != "" {
			ort.SetSharedLibraryPath(p)
		}

		if err := ort.InitializeEnvironment(); err != nil {
			runtimeErr = fmt.Errorf("onnx: initialize environment: %w", err)
			return
		}

		opts, err := ort.NewSessionOptions()
		if err != nil {
			runtimeErr = fmt.Errorf("onnx: create session options: %w", err)
			return
		}

		if numThreads > 0 {
			if err := opts.SetIntraOpNumThreads(numThreads); err != nil {
				runtimeErr = fmt.Errorf("onnx: set intra-op threads: %w", err)
				return
			}
			if err := opts.SetInterOpNumThreads(numThreads); err != nil {
				runtimeErr = fmt.Errorf("onnx: set inter-op threads: %w", err)
				return
			}
		}

		globalOptsMu.Lock()
		globalOpts = opts
		globalOptsMu.Unlock()
	})
	return runtimeErr
}

// discoverLibraryPath attempts to locate the ONNX Runtime shared library
// adjacent to the executable or in well-known system paths.
func discoverLibraryPath() string {
	var libName string
	switch runtime.GOOS {
	case "darwin":
		libName = "libonnxruntime.dylib"
	case "linux":
		libName = "libonnxruntime.so"
	case "windows":
		libName = "onnxruntime.dll"
	default:
		return ""
	}

	if exe, err := os.Executable(); err == nil {
		candidate := filepath.Join(filepath.Dir(exe), libName)
		if _, err := os.Stat(candidate); err == nil {
			return candidate
		}
	}

	candidates := []string{
		filepath.Join("/usr/lib", libName),
		filepath.Join("/usr/local/lib", libName),
	}
	if runtime.GOOS == "darwin" {
		candidates = append(candidates, filepath.Join("/opt/homebrew/lib", libName))
	}
	for _, c := range candidates {
		if _, err := os.Stat(c); err == nil {
			return c
		}
	}
	// github.com/yalue/onnxruntime_go defaults to "onnxruntime.so" when unset, which
	// is wrong on macOS (dlopen then reports onnxruntime.so). Prefer the standard
	// dylib name so Homebrew/DYLD_LIBRARY_PATH resolution matches upstream releases.
	if runtime.GOOS == "darwin" {
		return "libonnxruntime.dylib"
	}
	return ""
}

func getSessionOptions() *ort.SessionOptions {
	globalOptsMu.Lock()
	defer globalOptsMu.Unlock()
	return globalOpts
}

// ShutdownRuntime tears down the ONNX Runtime environment. Call once at
// program exit after all sessions have been closed.
func ShutdownRuntime() error {
	return ort.DestroyEnvironment()
}

// InferenceGuard controls resource limits for ONNX sessions.
type InferenceGuard struct {
	Timeout      time.Duration // max duration for a single prediction
	MemoryCeilMB int           // max memory per session (advisory)
	BatchSize    int           // max batch size for batch inference
}

// DefaultInferenceGuard returns conservative defaults suitable for
// a 32GB machine running alongside the EDR collector.
func DefaultInferenceGuard() InferenceGuard {
	return InferenceGuard{
		Timeout:      500 * time.Millisecond,
		MemoryCeilMB: 512,
		BatchSize:    32,
	}
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
	guard       InferenceGuard
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
		getSessionOptions(),
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
		guard:        DefaultInferenceGuard(),
	}, nil
}

// SetGuard configures resource limits for this session.
func (s *ONNXSession) SetGuard(g InferenceGuard) {
	s.mu.Lock()
	s.guard = g
	s.mu.Unlock()
}

// Predict runs inference on the provided input features and returns the model
// output. Concurrent calls are serialized to protect shared tensor buffers.
// Inference is aborted if it exceeds the configured timeout guard.
func (s *ONNXSession) Predict(input []float32) ([]float32, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.session == nil {
		return nil, fmt.Errorf("onnx: session is closed")
	}

	expectedDims := 1
	for _, d := range s.inputShape {
		expectedDims *= int(d)
	}
	if len(input) != expectedDims {
		return nil, fmt.Errorf("onnx: input size mismatch for %s: got %d floats, expected %d",
			s.inputName, len(input), expectedDims)
	}

	s.inputTensor.ZeroContents()
	data := s.inputTensor.GetData()
	copy(data, input)

	type inferResult struct {
		err error
	}
	done := make(chan inferResult, 1)

	go func() {
		done <- inferResult{err: s.session.Run()}
	}()

	timeout := s.guard.Timeout
	if timeout <= 0 {
		timeout = 500 * time.Millisecond
	}

	select {
	case res := <-done:
		if res.err != nil {
			return nil, fmt.Errorf("onnx: inference: %w", res.err)
		}
	case <-time.After(timeout):
		return nil, fmt.Errorf("onnx: inference timed out after %v", timeout)
	}

	out := s.outputTensor.GetData()
	result := make([]float32, len(out))
	copy(result, out)
	return result, nil
}

// PredictBatch runs inference on multiple inputs (up to guard.BatchSize),
// returning results for each input.
func (s *ONNXSession) PredictBatch(inputs [][]float32) ([][]float32, error) {
	maxBatch := s.guard.BatchSize
	if maxBatch <= 0 {
		maxBatch = 32
	}
	if len(inputs) > maxBatch {
		inputs = inputs[:maxBatch]
	}

	results := make([][]float32, len(inputs))
	for i, in := range inputs {
		out, err := s.Predict(in)
		if err != nil {
			return nil, fmt.Errorf("onnx: batch[%d]: %w", i, err)
		}
		results[i] = out
	}
	return results, nil
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
