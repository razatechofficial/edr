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
	modelPEClassifier        = "pe_classifier"
	modelBehaviorLSTM        = "behavior_lstm"
	modelNetworkAnomaly      = "network_anomaly"
	modelRansomware          = "ransomware"
	modelBehaviorTransformer = "behavior_transformer"
	modelLOLBin              = "lolbin_detector"
	modelSupplyChain         = "supply_chain_detector"
	modelAIGen               = "aigen_detector"
	modelIdentity            = "identity_threat"
	modelMemoryInjection    = "memory_injection"
	modelNetworkLGBM        = "network_lgbm"

	defaultPEMaliciousThreshold = 0.80

	defaultFilePEClassifier        = "pe_classifier.onnx"
	defaultFileBehaviorLSTM        = "behavior_lstm.onnx"
	defaultFileNetworkAnomaly      = "network_anomaly.onnx"
	defaultFileRansomware          = "ransomware.onnx"
	defaultFileBehaviorTransformer = "behavior_transformer.onnx"
	defaultFileLOLBin              = "lolbin_detector.onnx"
	defaultFileSupplyChain         = "supply_chain_detector.onnx"
	defaultFileAIGen               = "aigen_detector.onnx"
	defaultFileIdentity            = "identity_threat.onnx"
	defaultFileMemoryInjection    = "memory_injection.onnx"
	defaultFileNetworkLGBM        = "network_lgbm.onnx"
)

// Config holds settings for constructing a new ML Engine.
type Config struct {
	ModelsDir string

	// Model filenames (basename, resolved under ModelsDir). Empty = default.
	PEClassifierFile        string
	BehaviorLSTMFile        string
	NetworkAnomalyFile      string
	RansomwareFile          string
	BehaviorTransformerFile string
	LOLBinFile              string
	SupplyChainFile         string
	AIGenFile               string
	IdentityFile            string

	MemoryInjectionFile string
	NetworkLGBMFile     string

	// Hex-encoded Ed25519 public key for signature verification. Empty = off.
	VerifyPubKeyHex string

	// PEMaliciousThreshold is the score above which ScoreFile marks Malicious.
	// Zero defaults to 0.80 to match agent ML threshold defaults.
	PEMaliciousThreshold float64
}

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

// LOLBinScore contains the ML score for living-off-the-land binary abuse.
type LOLBinScore struct {
	Score      float64 `json:"score"`
	Confidence float64 `json:"confidence"`
	Category   string  `json:"category"`
}

// SupplyChainScore contains the ML score for supply chain attack indicators.
type SupplyChainScore struct {
	Score      float64 `json:"score"`
	Confidence float64 `json:"confidence"`
	Category   string  `json:"category"`
}

// AIGenScore contains the ML score for AI-generated malware detection.
type AIGenScore struct {
	Score      float64 `json:"score"`
	Confidence float64 `json:"confidence"`
	Category   string  `json:"category"`
}

// IdentityScore contains the ML score for identity/credential threat detection.
type IdentityScore struct {
	Score      float64 `json:"score"`
	Confidence float64 `json:"confidence"`
	Category   string  `json:"category"`
}

// MemoryInjectionScore contains the ML score for memory injection detection.
type MemoryInjectionScore struct {
	Score      float64 `json:"score"`
	Confidence float64 `json:"confidence"`
	Category   string  `json:"category"`
}

// ABTestMode controls how shadow/canary models are evaluated.
type ABTestMode int

const (
	// ABTestOff disables A/B testing.
	ABTestOff ABTestMode = iota
	// ABTestShadow runs both models, logs both scores, uses only primary.
	ABTestShadow
	// ABTestCanary routes a percentage of events to the candidate model.
	ABTestCanary
)

// ABTestConfig controls shadow/canary model deployment.
type ABTestConfig struct {
	Mode          ABTestMode
	CanaryPercent float64 // 0-100, used in Canary mode
}

// Engine orchestrates ML model inference for threat detection.
type Engine struct {
	models              *ModelManager
	peExtractor         *features.PEFeatureExtractor
	behavExtractor      *features.BehavioralFeatureExtractor
	transformerExtract  *features.TransformerFeatureExtractor
	netExtractor        *features.NetworkFeatureExtractor
	lolbinExtractor     *features.LOLBinFeatureExtractor
	supplyChainExtract  *features.SupplyChainFeatureExtractor
	aigenExtractor      *features.AIGenFeatureExtractor
	identityExtractor   *features.IdentityFeatureExtractor
	memInjectExtractor  *features.MemoryInjectionFeatureExtractor
	netLGBMExtractor    *features.NetworkFeatureExtractor
	logger              *zap.Logger
	enabled             bool
	peThreshold         float64
	abConfig            ABTestConfig
	shadowModels        *ModelManager
	inferenceCount      uint64
}

// NewEngine initializes the ML inference engine, loading available models from
// cfg.ModelsDir. Models that are not present on disk are skipped with a warning.
func NewEngine(cfg Config, logger *zap.Logger) (*Engine, error) {
	info, err := os.Stat(cfg.ModelsDir)
	if err != nil {
		return nil, fmt.Errorf("ml: models directory: %w", err)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("ml: %s is not a directory", cfg.ModelsDir)
	}

	var pubKeyBytes []byte
	if cfg.VerifyPubKeyHex != "" {
		b, err := hex.DecodeString(cfg.VerifyPubKeyHex)
		if err != nil {
			return nil, fmt.Errorf("ml: invalid verify_pubkey hex: %w", err)
		}
		pubKeyBytes = b
	}
	mgr := NewModelManager(pubKeyBytes)

	modelFiles := map[string]string{
		modelPEClassifier:        or(cfg.PEClassifierFile, defaultFilePEClassifier),
		modelBehaviorLSTM:        or(cfg.BehaviorLSTMFile, defaultFileBehaviorLSTM),
		modelNetworkAnomaly:      or(cfg.NetworkAnomalyFile, defaultFileNetworkAnomaly),
		modelRansomware:          or(cfg.RansomwareFile, defaultFileRansomware),
		modelBehaviorTransformer: or(cfg.BehaviorTransformerFile, defaultFileBehaviorTransformer),
		modelLOLBin:              or(cfg.LOLBinFile, defaultFileLOLBin),
		modelSupplyChain:         or(cfg.SupplyChainFile, defaultFileSupplyChain),
		modelAIGen:               or(cfg.AIGenFile, defaultFileAIGen),
		modelIdentity:            or(cfg.IdentityFile, defaultFileIdentity),
		modelMemoryInjection:    or(cfg.MemoryInjectionFile, defaultFileMemoryInjection),
		modelNetworkLGBM:        or(cfg.NetworkLGBMFile, defaultFileNetworkLGBM),
	}
	for name, file := range modelFiles {
		p := filepath.Join(cfg.ModelsDir, file)
		if _, statErr := os.Stat(p); statErr != nil {
			logger.Warn("ml: model not found, skipping",
				zap.String("model", name), zap.String("path", p))
			continue
		}
		if loadErr := mgr.Load(name, p); loadErr != nil {
			return nil, fmt.Errorf("ml: loading model %s: %w", name, loadErr)
		}
	}

	if err := mgr.LoadManifest(cfg.ModelsDir); err != nil {
		logger.Warn("ml: manifest not loaded (non-fatal)", zap.Error(err))
	} else if mgr.manifest != nil {
		logger.Info("ml: manifest loaded",
			zap.String("version", mgr.manifest.Version),
			zap.Int("model_count", len(mgr.manifest.Models)))
	}

	peThr := cfg.PEMaliciousThreshold
	if peThr <= 0 || peThr > 1 {
		peThr = defaultPEMaliciousThreshold
	}

	return &Engine{
		models:             mgr,
		peExtractor:        &features.PEFeatureExtractor{},
		behavExtractor:     features.NewBehavioralFeatureExtractor(50),
		transformerExtract: features.NewTransformerFeatureExtractor(0),
		netExtractor:       &features.NetworkFeatureExtractor{},
		lolbinExtractor:    &features.LOLBinFeatureExtractor{},
		supplyChainExtract: &features.SupplyChainFeatureExtractor{},
		aigenExtractor:     &features.AIGenFeatureExtractor{},
		identityExtractor:  &features.IdentityFeatureExtractor{},
		memInjectExtractor: &features.MemoryInjectionFeatureExtractor{},
		netLGBMExtractor:   &features.NetworkFeatureExtractor{},
		logger:             logger,
		enabled:            true,
		peThreshold:        peThr,
	}, nil
}

func or(val, fallback string) string {
	if val != "" {
		return val
	}
	return fallback
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
	if len(output) < 1 {
		return nil, fmt.Errorf("ml: pe model returned empty output")
	}

	hash, err := fileSHA256(path)
	if err != nil {
		return nil, fmt.Errorf("ml: hashing file: %w", err)
	}

	malScore := float64(output[0])
	return &FileScore{
		SHA256:     hash,
		Score:      malScore,
		Confidence: outputConfidence(output),
		Category:   classifyFileCategory(malScore),
		Malicious:  malScore >= e.peThreshold,
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

// ScoreProcessTransformer evaluates a variable-length event window using the
// behavior_transformer model for deeper contextual analysis.
func (e *Engine) ScoreProcessTransformer(ctx context.Context, eventWindow []interface{}) (*BehaviorScore, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if !e.enabled {
		return nil, fmt.Errorf("ml: engine is disabled")
	}

	feats := e.transformerExtract.Extract(eventWindow)

	session, err := e.models.Get(modelBehaviorTransformer)
	if err != nil {
		return nil, fmt.Errorf("ml: %w", err)
	}

	output, err := session.Predict(feats)
	if err != nil {
		return nil, fmt.Errorf("ml: behavior_transformer inference: %w", err)
	}
	if len(output) < 1 {
		return nil, fmt.Errorf("ml: behavior_transformer model returned empty output")
	}

	score := float64(output[0])
	return &BehaviorScore{
		Score:      score,
		Confidence: outputConfidence(output),
		Category:   classifyBehaviorCategory(score),
	}, nil
}

// ScoreProcessEnsemble scores using both LSTM and transformer models (when
// available), returning the higher-confidence result. Falls back to LSTM-only
// if the transformer model is not loaded.
func (e *Engine) ScoreProcessEnsemble(ctx context.Context, eventWindow []interface{}) (*BehaviorScore, error) {
	lstmScore, lstmErr := e.ScoreProcess(ctx, eventWindow)

	transformerScore, transformerErr := e.ScoreProcessTransformer(ctx, eventWindow)
	if transformerErr != nil {
		if lstmErr != nil {
			return nil, lstmErr
		}
		return lstmScore, nil
	}
	if lstmErr != nil {
		return transformerScore, nil
	}

	if transformerScore.Confidence >= lstmScore.Confidence {
		return transformerScore, nil
	}
	return lstmScore, nil
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

// ScoreNetworkLGBM evaluates a network connection using the supervised
// LightGBM model. Returns 0 if the model is not loaded (non-fatal).
func (e *Engine) ScoreNetworkLGBM(ctx context.Context, conn interface{}) (*NetworkScore, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if !e.enabled {
		return nil, fmt.Errorf("ml: engine is disabled")
	}

	feats := e.netLGBMExtractor.Extract(conn)

	session, err := e.models.Get(modelNetworkLGBM)
	if err != nil {
		return nil, fmt.Errorf("ml: %w", err)
	}

	output, err := session.Predict(feats)
	if err != nil {
		return nil, fmt.Errorf("ml: network_lgbm inference: %w", err)
	}
	if len(output) < 1 {
		return nil, fmt.Errorf("ml: network_lgbm model returned empty output")
	}

	score := float64(output[0])
	return &NetworkScore{
		Score:      score,
		Confidence: outputConfidence(output),
		Category:   classifyNetworkCategory(score),
	}, nil
}

// ScoreNetworkEnsemble scores using both autoencoder and supervised LGBM
// models, returning the higher-confidence result. Falls back to autoencoder
// only if LGBM is not loaded.
func (e *Engine) ScoreNetworkEnsemble(ctx context.Context, conn interface{}) (*NetworkScore, error) {
	autoScore, autoErr := e.ScoreNetwork(ctx, conn)
	lgbmScore, lgbmErr := e.ScoreNetworkLGBM(ctx, conn)
	if lgbmErr != nil {
		if autoErr != nil {
			return nil, autoErr
		}
		return autoScore, nil
	}
	if autoErr != nil {
		return lgbmScore, nil
	}
	if lgbmScore.Confidence >= autoScore.Confidence {
		return lgbmScore, nil
	}
	return autoScore, nil
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

// ScoreLOLBin evaluates a process event for living-off-the-land binary abuse.
func (e *Engine) ScoreLOLBin(ctx context.Context, evt interface{}) (*LOLBinScore, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if !e.enabled {
		return nil, fmt.Errorf("ml: engine is disabled")
	}

	feats := e.lolbinExtractor.Extract(evt)

	session, err := e.models.Get(modelLOLBin)
	if err != nil {
		return nil, fmt.Errorf("ml: %w", err)
	}

	output, err := session.Predict(feats)
	if err != nil {
		return nil, fmt.Errorf("ml: lolbin inference: %w", err)
	}
	if len(output) < 1 {
		return nil, fmt.Errorf("ml: lolbin model returned empty output")
	}

	score := float64(output[0])
	return &LOLBinScore{
		Score:      score,
		Confidence: outputConfidence(output),
		Category:   classifyLOLBinCategory(score),
	}, nil
}

// ScoreSupplyChain evaluates binary/update metadata for supply chain tampering.
func (e *Engine) ScoreSupplyChain(ctx context.Context, evt interface{}) (*SupplyChainScore, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if !e.enabled {
		return nil, fmt.Errorf("ml: engine is disabled")
	}

	feats := e.supplyChainExtract.Extract(evt)

	session, err := e.models.Get(modelSupplyChain)
	if err != nil {
		return nil, fmt.Errorf("ml: %w", err)
	}

	output, err := session.Predict(feats)
	if err != nil {
		return nil, fmt.Errorf("ml: supply_chain inference: %w", err)
	}
	if len(output) < 1 {
		return nil, fmt.Errorf("ml: supply_chain model returned empty output")
	}

	score := float64(output[0])
	return &SupplyChainScore{
		Score:      score,
		Confidence: outputConfidence(output),
		Category:   classifySupplyChainCategory(score),
	}, nil
}

// ScoreAIGen evaluates executable characteristics for AI-generated malware.
func (e *Engine) ScoreAIGen(ctx context.Context, evt interface{}) (*AIGenScore, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if !e.enabled {
		return nil, fmt.Errorf("ml: engine is disabled")
	}

	feats := e.aigenExtractor.Extract(evt)

	session, err := e.models.Get(modelAIGen)
	if err != nil {
		return nil, fmt.Errorf("ml: %w", err)
	}

	output, err := session.Predict(feats)
	if err != nil {
		return nil, fmt.Errorf("ml: aigen inference: %w", err)
	}
	if len(output) < 1 {
		return nil, fmt.Errorf("ml: aigen model returned empty output")
	}

	score := float64(output[0])
	return &AIGenScore{
		Score:      score,
		Confidence: outputConfidence(output),
		Category:   classifyAIGenCategory(score),
	}, nil
}

// ScoreIdentity evaluates authentication events for credential threats.
func (e *Engine) ScoreIdentity(ctx context.Context, evt interface{}) (*IdentityScore, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if !e.enabled {
		return nil, fmt.Errorf("ml: engine is disabled")
	}

	feats := e.identityExtractor.Extract(evt)

	session, err := e.models.Get(modelIdentity)
	if err != nil {
		return nil, fmt.Errorf("ml: %w", err)
	}

	output, err := session.Predict(feats)
	if err != nil {
		return nil, fmt.Errorf("ml: identity inference: %w", err)
	}
	if len(output) < 1 {
		return nil, fmt.Errorf("ml: identity model returned empty output")
	}

	score := float64(output[0])
	return &IdentityScore{
		Score:      score,
		Confidence: outputConfidence(output),
		Category:   classifyIdentityCategory(score),
	}, nil
}

// ScoreMemoryInjection evaluates memory scan data for process injection
// indicators such as RWX regions, PE headers in non-module memory, high entropy
// executable regions, and unbacked memory mappings.
func (e *Engine) ScoreMemoryInjection(ctx context.Context, evt interface{}) (*MemoryInjectionScore, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if !e.enabled {
		return nil, fmt.Errorf("ml: engine is disabled")
	}

	feats := e.memInjectExtractor.Extract(evt)

	session, err := e.models.Get(modelMemoryInjection)
	if err != nil {
		return nil, fmt.Errorf("ml: %w", err)
	}

	output, err := session.Predict(feats)
	if err != nil {
		return nil, fmt.Errorf("ml: memory_injection inference: %w", err)
	}
	if len(output) < 1 {
		return nil, fmt.Errorf("ml: memory_injection model returned empty output")
	}

	score := float64(output[0])
	return &MemoryInjectionScore{
		Score:      score,
		Confidence: outputConfidence(output),
		Category:   classifyMemoryInjectionCategory(score),
	}, nil
}

// Enabled reports whether the ML engine is currently active.
func (e *Engine) Enabled() bool { return e.enabled }

// SetEnabled toggles the ML engine on or off.
func (e *Engine) SetEnabled(v bool) { e.enabled = v }

// Models returns the underlying ModelManager for advanced operations such as
// hot-swapping or direct session access.
func (e *Engine) Models() *ModelManager { return e.models }

// SetABTestConfig configures shadow/canary testing mode.
func (e *Engine) SetABTestConfig(cfg ABTestConfig) { e.abConfig = cfg }

// SetShadowModels configures a secondary model manager for A/B testing.
func (e *Engine) SetShadowModels(m *ModelManager) { e.shadowModels = m }

// shouldUseCandidate returns true if this inference should route to the
// candidate model (in canary mode).
func (e *Engine) shouldUseCandidate() bool {
	if e.abConfig.Mode != ABTestCanary || e.abConfig.CanaryPercent <= 0 {
		return false
	}
	e.inferenceCount++
	return float64(e.inferenceCount%100) < e.abConfig.CanaryPercent
}

// scoreShadow runs the shadow model if A/B testing is active, logging
// the result but not returning it to the caller.
func (e *Engine) scoreShadow(modelName string, feats []float32) {
	if e.abConfig.Mode != ABTestShadow || e.shadowModels == nil {
		return
	}
	session, err := e.shadowModels.Get(modelName)
	if err != nil {
		return
	}
	output, err := session.Predict(feats)
	if err != nil {
		e.logger.Debug("shadow model inference failed",
			zap.String("model", modelName), zap.Error(err))
		return
	}
	if len(output) > 0 {
		e.logger.Debug("shadow model score",
			zap.String("model", modelName),
			zap.Float32("shadow_score", output[0]))
	}
}

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

func classifyLOLBinCategory(score float64) string {
	switch {
	case score >= 0.9:
		return "lolbin_abuse"
	case score >= 0.7:
		return "suspicious_tool_usage"
	case score >= 0.4:
		return "unusual_invocation"
	default:
		return "normal"
	}
}

func classifySupplyChainCategory(score float64) string {
	switch {
	case score >= 0.9:
		return "supply_chain_compromise"
	case score >= 0.7:
		return "tampered_binary"
	case score >= 0.4:
		return "update_anomaly"
	default:
		return "normal"
	}
}

func classifyAIGenCategory(score float64) string {
	switch {
	case score >= 0.9:
		return "ai_generated_malware"
	case score >= 0.7:
		return "machine_generated_suspicious"
	case score >= 0.4:
		return "synthetic_code_patterns"
	default:
		return "normal"
	}
}

func classifyIdentityCategory(score float64) string {
	switch {
	case score >= 0.9:
		return "credential_compromise"
	case score >= 0.7:
		return "suspicious_authentication"
	case score >= 0.4:
		return "authentication_anomaly"
	default:
		return "normal"
	}
}

func classifyMemoryInjectionCategory(score float64) string {
	switch {
	case score >= 0.9:
		return "active_injection"
	case score >= 0.7:
		return "suspicious_memory"
	case score >= 0.4:
		return "anomalous_allocation"
	default:
		return "normal"
	}
}
