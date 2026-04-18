// Tests for pure-Go helpers in engine.go. Full integration tests that require
// ONNX sessions are deferred until the runtime library is available.

//go:build cgo && (linux || darwin || windows)

package ml

import (
	"os"
	"path/filepath"
	"testing"
)

func TestClassifyFileCategory(t *testing.T) {
	tests := []struct {
		score    float64
		expected string
	}{
		{0.95, "malware"},
		{0.9, "malware"},
		{0.75, "suspicious"},
		{0.7, "suspicious"},
		{0.55, "potentially_unwanted"},
		{0.5, "potentially_unwanted"},
		{0.3, "benign"},
		{0.0, "benign"},
	}
	for _, tc := range tests {
		got := classifyFileCategory(tc.score)
		if got != tc.expected {
			t.Errorf("classifyFileCategory(%f) = %q, want %q", tc.score, got, tc.expected)
		}
	}
}

func TestClassifyBehaviorCategory(t *testing.T) {
	tests := []struct {
		score    float64
		expected string
	}{
		{0.95, "malicious_behavior"},
		{0.75, "suspicious_behavior"},
		{0.5, "anomalous_behavior"},
		{0.3, "normal"},
	}
	for _, tc := range tests {
		got := classifyBehaviorCategory(tc.score)
		if got != tc.expected {
			t.Errorf("classifyBehaviorCategory(%f) = %q, want %q", tc.score, got, tc.expected)
		}
	}
}

func TestClassifyNetworkCategory(t *testing.T) {
	tests := []struct {
		score    float64
		expected string
	}{
		{0.95, "c2_communication"},
		{0.75, "suspicious_traffic"},
		{0.5, "anomalous_traffic"},
		{0.2, "normal"},
	}
	for _, tc := range tests {
		got := classifyNetworkCategory(tc.score)
		if got != tc.expected {
			t.Errorf("classifyNetworkCategory(%f) = %q, want %q", tc.score, got, tc.expected)
		}
	}
}

func TestClassifyRansomwareCategory(t *testing.T) {
	tests := []struct {
		score    float64
		expected string
	}{
		{0.95, "active_ransomware"},
		{0.75, "ransomware_precursor"},
		{0.5, "suspicious_encryption"},
		{0.1, "normal"},
	}
	for _, tc := range tests {
		got := classifyRansomwareCategory(tc.score)
		if got != tc.expected {
			t.Errorf("classifyRansomwareCategory(%f) = %q, want %q", tc.score, got, tc.expected)
		}
	}
}

func TestClassifyLOLBinCategory(t *testing.T) {
	tests := []struct {
		score    float64
		expected string
	}{
		{0.95, "lolbin_abuse"},
		{0.75, "suspicious_tool_usage"},
		{0.5, "unusual_invocation"},
		{0.2, "normal"},
	}
	for _, tc := range tests {
		got := classifyLOLBinCategory(tc.score)
		if got != tc.expected {
			t.Errorf("classifyLOLBinCategory(%f) = %q, want %q", tc.score, got, tc.expected)
		}
	}
}

func TestClassifySupplyChainCategory(t *testing.T) {
	tests := []struct {
		score    float64
		expected string
	}{
		{0.95, "supply_chain_compromise"},
		{0.75, "tampered_binary"},
		{0.5, "update_anomaly"},
		{0.2, "normal"},
	}
	for _, tc := range tests {
		got := classifySupplyChainCategory(tc.score)
		if got != tc.expected {
			t.Errorf("classifySupplyChainCategory(%f) = %q, want %q", tc.score, got, tc.expected)
		}
	}
}

func TestClassifyAIGenCategory(t *testing.T) {
	tests := []struct {
		score    float64
		expected string
	}{
		{0.95, "ai_generated_malware"},
		{0.75, "machine_generated_suspicious"},
		{0.5, "synthetic_code_patterns"},
		{0.2, "normal"},
	}
	for _, tc := range tests {
		got := classifyAIGenCategory(tc.score)
		if got != tc.expected {
			t.Errorf("classifyAIGenCategory(%f) = %q, want %q", tc.score, got, tc.expected)
		}
	}
}

func TestClassifyIdentityCategory(t *testing.T) {
	tests := []struct {
		score    float64
		expected string
	}{
		{0.95, "credential_compromise"},
		{0.75, "suspicious_authentication"},
		{0.5, "authentication_anomaly"},
		{0.2, "normal"},
	}
	for _, tc := range tests {
		got := classifyIdentityCategory(tc.score)
		if got != tc.expected {
			t.Errorf("classifyIdentityCategory(%f) = %q, want %q", tc.score, got, tc.expected)
		}
	}
}

func TestSoftmaxConfidence(t *testing.T) {
	tests := []struct {
		name   string
		output []float32
		want   float64
	}{
		{"two outputs", []float32{0.2, 0.8}, 0.8},
		{"equal outputs", []float32{0.5, 0.5}, 0.5},
		{"single output", []float32{0.9}, 0.0},
		{"zero sum", []float32{0.0, 0.0}, 0.0},
	}
	for _, tc := range tests {
		got := softmaxConfidence(tc.output)
		if diff := got - tc.want; diff > 0.001 || diff < -0.001 {
			t.Errorf("softmaxConfidence(%s) = %f, want %f", tc.name, got, tc.want)
		}
	}
}

func TestOutputConfidence(t *testing.T) {
	if outputConfidence(nil) != 0 {
		t.Error("empty output should return 0")
	}

	got := outputConfidence([]float32{0.8})
	if diff := got - 0.8; diff > 0.001 || diff < -0.001 {
		t.Errorf("single output 0.8 should return 0.8, got %f", got)
	}

	got = outputConfidence([]float32{0.3})
	if diff := got - 0.7; diff > 0.001 || diff < -0.001 {
		t.Errorf("single output 0.3 should return 0.7, got %f", got)
	}

	got = outputConfidence([]float32{0.2, 0.8})
	if diff := got - 0.8; diff > 0.001 || diff < -0.001 {
		t.Errorf("two outputs should use softmax, got %f", got)
	}
}

func TestEncodeRansomwareIndicators(t *testing.T) {
	indicators := map[string]float64{
		"entropy_increase_rate":  0.9,
		"shadow_copy_deletion":   1.0,
		"file_rename_rate":       0.5,
		"nonexistent_key":        0.7,
	}
	feats := encodeRansomwareIndicators(indicators)
	if len(feats) != len(ransomwareFeatureKeys) {
		t.Fatalf("expected %d features, got %d", len(ransomwareFeatureKeys), len(feats))
	}
	if feats[0] != 0.9 {
		t.Errorf("entropy_increase_rate should be 0.9, got %f", feats[0])
	}
	if feats[1] != 0.5 {
		t.Errorf("file_rename_rate should be 0.5, got %f", feats[1])
	}
	if feats[6] != 1.0 {
		t.Errorf("shadow_copy_deletion should be 1.0, got %f", feats[6])
	}
}

func TestEncodeRansomwareIndicators_Empty(t *testing.T) {
	feats := encodeRansomwareIndicators(nil)
	for i, v := range feats {
		if v != 0 {
			t.Errorf("empty indicators should be all zeros, got non-zero at [%d]=%f", i, v)
		}
	}
}

func TestOrHelper(t *testing.T) {
	if or("a", "b") != "a" {
		t.Error("or with non-empty val should return val")
	}
	if or("", "fallback") != "fallback" {
		t.Error("or with empty val should return fallback")
	}
}

func TestFileSHA256(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "test.bin")
	if err := os.WriteFile(p, []byte("hello world"), 0644); err != nil {
		t.Fatal(err)
	}
	hash, err := fileSHA256(p)
	if err != nil {
		t.Fatal(err)
	}
	// SHA-256 of "hello world"
	expected := "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
	if hash != expected {
		t.Errorf("expected %s, got %s", expected, hash)
	}
}

func TestFileSHA256_NotFound(t *testing.T) {
	_, err := fileSHA256("/nonexistent/path")
	if err == nil {
		t.Error("expected error for nonexistent file")
	}
}

func TestNewEngine_InvalidDir(t *testing.T) {
	_, err := NewEngine(Config{ModelsDir: "/nonexistent/dir"}, nil)
	if err == nil {
		t.Error("expected error for nonexistent models directory")
	}
}

func TestNewEngine_InvalidHexKey(t *testing.T) {
	dir := t.TempDir()
	_, err := NewEngine(Config{
		ModelsDir:       dir,
		VerifyPubKeyHex: "not-valid-hex",
	}, nil)
	if err == nil {
		t.Error("expected error for invalid hex public key")
	}
}

func TestABTestConfig_Defaults(t *testing.T) {
	var cfg ABTestConfig
	if cfg.Mode != ABTestOff {
		t.Error("default AB test mode should be Off")
	}
	if cfg.CanaryPercent != 0 {
		t.Error("default canary percent should be 0")
	}
}
