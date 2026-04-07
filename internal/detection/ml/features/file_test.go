package features

import (
	"os"
	"path/filepath"
	"testing"
)

func TestPEFeatureExtractorExtract_NonExecutable(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	sample := filepath.Join(tmp, "sample.bin")
	if err := os.WriteFile(sample, []byte("hello world"), 0o600); err != nil {
		t.Fatalf("write sample: %v", err)
	}

	ex := &PEFeatureExtractor{}
	feats, err := ex.Extract(sample)
	if err != nil {
		t.Fatalf("extract features: %v", err)
	}
	if len(feats) != TotalFileFeatures {
		t.Fatalf("unexpected feature count: got=%d want=%d", len(feats), TotalFileFeatures)
	}
	var histSum float32
	for i := 0; i < byteHistogramSize; i++ {
		histSum += feats[i]
	}
	if histSum <= 0 {
		t.Fatalf("byte histogram appears empty for non-empty file")
	}
}
