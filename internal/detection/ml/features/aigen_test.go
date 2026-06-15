package features

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type mockAIGenCode struct {
	code string
}

func (m mockAIGenCode) GetCommandLine() string {
	return m.code
}

func writeTestCode(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "test_code.py")
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	return path
}

type mockPath struct {
	path string
}

func (m mockPath) GetPath() string {
	return m.path
}

func TestAIGenExtractor_FeatureCount(t *testing.T) {
	ext := &AIGenFeatureExtractor{}
	feats := ext.Extract(mockAIGenCode{code: "print('hello')"})
	if len(feats) != AIGenFeatureCount {
		t.Fatalf("expected %d features, got %d", AIGenFeatureCount, len(feats))
	}
}

func TestAIGenExtractor_EmptyEvent(t *testing.T) {
	ext := &AIGenFeatureExtractor{}
	feats := ext.Extract("not-a-real-event")
	for i, v := range feats {
		if v != 0 {
			t.Fatalf("expected all zeros, got non-zero at [%d]=%f", i, v)
		}
	}
}

func TestAIGenExtractor_FromCommandLine(t *testing.T) {
	ext := &AIGenFeatureExtractor{}
	code := `def hello():
    print("hello world")
`
	feats := ext.Extract(mockAIGenCode{code: code})
	if len(feats) != AIGenFeatureCount {
		t.Fatalf("expected %d features, got %d", AIGenFeatureCount, len(feats))
	}
	// Feature 0: std of line lengths (should be small for 2 lines)
	if feats[0] < 0 || feats[0] > 1 {
		t.Errorf("line length std out of range [0,1]: %f", feats[0])
	}
	// Feature 1: mean line length
	if feats[1] <= 0 {
		t.Errorf("mean line length should be > 0, got %f", feats[1])
	}
}

func TestAIGenExtractor_FromFilePath(t *testing.T) {
	ext := &AIGenFeatureExtractor{}
	code := `for i in range(10):
    if i % 2 == 0:
        print(i)
`
	path := writeTestCode(t, code)
	feats := ext.Extract(mockPath{path: path})
	if len(feats) != AIGenFeatureCount {
		t.Fatalf("expected %d features, got %d", AIGenFeatureCount, len(feats))
	}
	// Should have non-zero features from parsing the Python code
	if feats[16] <= 0 {
		t.Errorf("branch count feature should be positive for code with for/if, got %f", feats[16])
	}
}

func TestAIGenExtractor_CodeComplexity(t *testing.T) {
	ext := &AIGenFeatureExtractor{}
	code := `def process(data):
    result = []
    for i in range(len(data)):
        if data[i] > 0:
            val = transform(data[i])
            if val is not None:
                result.append(val)
    return result
`
	feats := ext.Extract(mockAIGenCode{code: code})
	// Branch count (for, if, if)
	if feats[16] <= 0 {
		t.Errorf("branch count expected > 0, got %f", feats[16])
	}
	// Function definitions
	if feats[17] <= 0 {
		t.Errorf("func def count expected > 0, got %f", feats[17])
	}
	// Naming conventions - check func calls
	if feats[28] <= 0 {
		t.Errorf("func call ratio expected > 0, got %f", feats[28])
	}
}

func TestAIGenExtractor_BinaryFileFallsBack(t *testing.T) {
	ext := &AIGenFeatureExtractor{}
	binContent := []byte{0x00, 0x01, 0x02, 0x03, 0xFF, 0xFE, 0xFD, 0xFC}
	path := filepath.Join(t.TempDir(), "test.bin")
	if err := os.WriteFile(path, binContent, 0644); err != nil {
		t.Fatal(err)
	}
	feats := ext.Extract(mockPath{path: path})
	// Binary files without text should return near-zero features
	if len(feats) != AIGenFeatureCount {
		t.Fatalf("expected %d features, got %d", AIGenFeatureCount, len(feats))
	}
}

func TestAIGenExtractor_NonExistentFile(t *testing.T) {
	ext := &AIGenFeatureExtractor{}
	feats := ext.Extract(mockPath{path: "/nonexistent/file.py"})
	for i, v := range feats {
		if v != 0 {
			t.Fatalf("expected all zeros for non-existent file, got non-zero at [%d]=%f", i, v)
		}
	}
}

func TestAIGenExtractor_ObfuscationFeatures(t *testing.T) {
	code := strings.Repeat("a ", 300)
	feats := (&AIGenFeatureExtractor{}).Extract(mockAIGenCode{code: code})
	// Repetitive content should have no obfuscation patterns
	if feats[32] != 0 {
		t.Errorf("expected no base64 patterns, got %f", feats[32])
	}
}

func TestAIGenExtractor_CommentProfile(t *testing.T) {
	code := `# this is a comment
# another comment
# yet another comment
code_line = 1
`
	feats := (&AIGenFeatureExtractor{}).Extract(mockAIGenCode{code: code})
	// comment ratio (feature 8): 3 comment lines / 4 non-blank lines
	if feats[8] <= 0 {
		t.Errorf("comment ratio expected > 0, got %f", feats[8])
	}
	if feats[11] <= 0 {
		t.Errorf("comment-to-code ratio expected > 0, got %f", feats[11])
	}
}
