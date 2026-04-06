package ml

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"go.uber.org/zap"

	"github.com/razatechofficial/edr/internal/detection/ml/features"
)

const (
	modelPEClassifier   = "pe_classifier"
	modelBehaviorLSTM   = "behavior_lstm"
	modelNetworkAnomaly = "network_anomaly"
	modelRansomware     = "ransomware"

	defaultMalwareThreshold = 0.5
)

// FileScore contains the ML classification result for an executable file.
type FileScore struct {
	SHA256     string  `json:"sha256"`
	Score      float64 `json:"score"`
	Confidence float64 `json:"confidence"`
	Category   string  `json:"category"`
	Malicious  bool    `json:"malicious"`
}

// BehaviorScore contains the ML classification result for a process behavior
// sequence.
type BehaviorScore struct {
	Score      float64 `json:"score"`
	Confidence float64 `json:"confidence"`
	Category   string  `json:"category"`
}

// NetworkScore contains the ML anomaly detection result for a network
// connection.
type NetworkScore struct {
	Score      float64 `json:"score"`
	Confidence float64 `json:"confidence"`
	Category   string  `json:"category"`
}

// RansomwareScore contains the ML classification result for ransomware
// indicators.
type RansomwareScore struct {
	Score      float64 `json:"score"`
	Confidence float64 `json:"confidence"`
	Category   string  `json:"category"`
}

// Engine orchestrates ML model inference for threat detection.
type Engine struct {
	models         *ModelManager
	peExtractor    *features.PEFeatureExtractor
	behavExtractor *features.BehavioralFeatureExtractor
	netExtractor   *features.NetworkFeatureExtractor
	logger         *zap.Logger
	enabled        bool
}

// NewEngine initializes the ML inference engine, loading available models from
// modelsDir. Models that are not present on disk are skipped with a warning.
func NewEngine(modelsDir string, logger *zap.Logger) (*Engine, error) {
	info, err := os.Stat(modelsDir)
	if err != nil {
		return nil, fmt.Errorf("ml: models directory: %w", err)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("ml: %s is not a directory", modelsDir)
	}

	mgr := NewModelManager(nil)

	modelFiles := map[string]string{
		modelPEClassifier:   "pe_classifier.onnx",
		modelBehaviorLSTM:   "behavior_lstm.onnx",
		modelNetworkAnomaly: "network_anomaly.onnx",
		modelRansomware:     "ransomware.onnx",
	}
	for name, file := range modelFiles {
		p := filepath.Join(modelsDir, file)
		if _, statErr := os.Stat(p); statErr != nil {
			logger.Warn("ml: model not found, skipping",
				zap.String("model", name), zap.String("path", p))
			continue
		}
		if loadErr := mgr.Load(name, p); loadErr != nil {
			return nil, fmt.Errorf("ml: loading model %s: %w", name, loadErr)
		}
	}

	return &Engine{
		models:         mgr,
		peExtractor:    &features.PEFeatureExtractor{},
		behavExtractor: features.NewBehavioralFeatureExtractor(50),
		netExtractor:   &features.NetworkFeatureExtractor{},
		logger:         logger,
		enabled:        true,
	}, nil
}

// ScoreFile classifies an executable file (PE/ELF/Mach-O) as malicious or
// benign. The returned FileScore includes the SHA-256 hash of the file.
func (e *Engine) ScoreFile(ctx context.Context, path string) (*FileScore, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if !e.enabled {
		return nil, fmt.Errorf("ml: engine is disabled")
	}

	feats, err := e.peExtractor.Extract(path)
	if err != nil {
		return nil, fmt.Errorf("ml: file feature extraction: %w", err)
	}

	session, err := e.models.Get(modelPEClassifier)
	if err != nil {
		return nil, fmt.Errorf("ml: %w", err)
	}

	output, err := session.Predict(feats)
	if err != nil {
		return nil, fmt.Errorf("ml: pe inference: %w", err)
	}
	if len(output) < 2 {
		return nil, fmt.Errorf("ml: pe model returned %d outputs, expected >= 2", len(output))
	}

	hash, err := fileSHA256(path)
	if err != nil {
		return nil, fmt.Errorf("ml: hashing file: %w", err)
	}

	malScore := float64(output[1])
	return &FileScore{
		SHA256:     hash,
		Score:      malScore,
		Confidence: softmaxConfidence(output),
		Category:   classifyFileCategory(malScore),
		Malicious:  malScore >= defaultMalwareThreshold,
	}, nil
}

// ScoreProcess evaluates a window of process events using the behavioral LSTM
// model.
func (e *Engine) ScoreProcess(ctx context.Context, eventWindow []interface{}) (*BehaviorScore, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if !e.enabled {
		return nil, fmt.Errorf("ml: engine is disabled")
	}

	feats := e.behavExtractor.Extract(eventWindow)

	session, err := e.models.Get(modelBehaviorLSTM)
	if err != nil {
		return nil, fmt.Errorf("ml: %w", err)
	}

	output, err := session.Predict(feats)
	if err != nil {
		return nil, fmt.Errorf("ml: behavior inference: %w", err)
	}
	if len(output) < 1 {
		return nil, fmt.Errorf("ml: behavior model returned empty output")
	}

	score := float64(output[0])
	return &BehaviorScore{
		Score:      score,
		Confidence: outputConfidence(output),
		Category:   classifyBehaviorCategory(score),
	}, nil
}

// ScoreNetwork evaluates a network connection for anomalous behavior.
func (e *Engine) ScoreNetwork(ctx context.Context, conn interface{}) (*NetworkScore, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if !e.enabled {
		return nil, fmt.Errorf("ml: engine is disabled")
	}

	feats := e.netExtractor.Extract(conn)

	session, err := e.models.Get(modelNetworkAnomaly)
	if err != nil {
		return nil, fmt.Errorf("ml: %w", err)
	}

	output, err := session.Predict(feats)
	if err != nil {
		return nil, fmt.Errorf("ml: network inference: %w", err)
	}
	if len(output) < 1 {
		return nil, fmt.Errorf("ml: network model returned empty output")
	}

	score := float64(output[0])
	return &NetworkScore{
		Score:      score,
		Confidence: outputConfidence(output),
		Category:   classifyNetworkCategory(score),
	}, nil
}

// ScoreRansomware evaluates ransomware-specific indicators. The indicators map
// should contain keys from the ransomwareFeatureKeys set with values in [0,1].
func (e *Engine) ScoreRansomware(ctx context.Context, indicators map[string]float64) (*RansomwareScore, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if !e.enabled {
		return nil, fmt.Errorf("ml: engine is disabled")
	}

	feats := encodeRansomwareIndicators(indicators)

	session, err := e.models.Get(modelRansomware)
	if err != nil {
		return nil, fmt.Errorf("ml: %w", err)
	}

	output, err := session.Predict(feats)
	if err != nil {
		return nil, fmt.Errorf("ml: ransomware inference: %w", err)
	}
	if len(output) < 1 {
		return nil, fmt.Errorf("ml: ransomware model returned empty output")
	}

	score := float64(output[0])
	return &RansomwareScore{
		Score:      score,
		Confidence: outputConfidence(output),
		Category:   classifyRansomwareCategory(score),
	}, nil
}

// Enabled reports whether the ML engine is currently active.
func (e *Engine) Enabled() bool { return e.enabled }

// SetEnabled toggles the ML engine on or off.
func (e *Engine) SetEnabled(v bool) { e.enabled = v }

// Models returns the underlying ModelManager for advanced operations such as
// hot-swapping or direct session access.
func (e *Engine) Models() *ModelManager { return e.models }

// --- helpers ---

func fileSHA256(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func softmaxConfidence(output []float32) float64 {
	if len(output) < 2 {
		return 0
	}
	mx := output[0]
	var sum float32
	for _, v := range output {
		sum += v
		if v > mx {
			mx = v
		}
	}
	if sum == 0 {
		return 0
	}
	return float64(mx) / float64(sum)
}

func outputConfidence(output []float32) float64 {
	if len(output) == 0 {
		return 0
	}
	if len(output) == 1 {
		s := float64(output[0])
		if s > 0.5 {
			return s
		}
		return 1.0 - s
	}
	return softmaxConfidence(output)
}

var ransomwareFeatureKeys = [...]string{
	"entropy_increase_rate",
	"file_rename_rate",
	"file_delete_rate",
	"file_type_change_rate",
	"known_extension_append",
	"ransom_note_similarity",
	"shadow_copy_deletion",
	"encryption_api_calls",
	"network_beacon_rate",
	"unique_file_extensions",
}

func encodeRansomwareIndicators(indicators map[string]float64) []float32 {
	feats := make([]float32, len(ransomwareFeatureKeys))
	for i, key := range ransomwareFeatureKeys {
		feats[i] = float32(indicators[key])
	}
	return feats
}

func classifyFileCategory(score float64) string {
	switch {
	case score >= 0.9:
		return "malware"
	case score >= 0.7:
		return "suspicious"
	case score >= 0.5:
		return "potentially_unwanted"
	default:
		return "benign"
	}
}

func classifyBehaviorCategory(score float64) string {
	switch {
	case score >= 0.9:
		return "malicious_behavior"
	case score >= 0.7:
		return "suspicious_behavior"
	case score >= 0.4:
		return "anomalous_behavior"
	default:
		return "normal"
	}
}

func classifyNetworkCategory(score float64) string {
	switch {
	case score >= 0.9:
		return "c2_communication"
	case score >= 0.7:
		return "suspicious_traffic"
	case score >= 0.4:
		return "anomalous_traffic"
	default:
		return "normal"
	}
}

func classifyRansomwareCategory(score float64) string {
	switch {
	case score >= 0.9:
		return "active_ransomware"
	case score >= 0.7:
		return "ransomware_precursor"
	case score >= 0.4:
		return "suspicious_encryption"
	default:
		return "normal"
	}
}
