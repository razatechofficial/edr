//go:build cgo

package rules

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"go.uber.org/zap"
)

const testYARARule = `rule TestEicar {
    meta:
        description = "Test EICAR-like detection"
        severity = "high"
    strings:
        $s1 = "EICAR-STANDARD-ANTIVIRUS-TEST-FILE"
    condition:
        any of them
}
`

func writeYARARule(t *testing.T, dir string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, "test.yar"), []byte(testYARARule), 0o644); err != nil {
		t.Fatalf("write yara rule: %v", err)
	}
}

func TestYARAEngineLoadRules(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	writeYARARule(t, dir)

	logger, _ := zap.NewDevelopment()
	engine, err := NewYARAEngine(dir, 50, 2, logger)
	if err != nil {
		t.Fatalf("NewYARAEngine: %v", err)
	}
	defer engine.Stop()

	if engine.Count() != 1 {
		t.Errorf("Count() = %d, want 1", engine.Count())
	}
}

func TestYARAScanFileMatch(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	writeYARARule(t, dir)

	logger, _ := zap.NewDevelopment()
	engine, err := NewYARAEngine(dir, 50, 2, logger)
	if err != nil {
		t.Fatalf("NewYARAEngine: %v", err)
	}
	defer engine.Stop()

	target := filepath.Join(t.TempDir(), "suspect.bin")
	content := "prefix EICAR-STANDARD-ANTIVIRUS-TEST-FILE suffix"
	os.WriteFile(target, []byte(content), 0o644)

	matches, err := engine.ScanFile(context.Background(), target)
	if err != nil {
		t.Fatalf("ScanFile: %v", err)
	}
	if len(matches) == 0 {
		t.Fatal("ScanFile returned 0 matches for EICAR-like content")
	}
	if matches[0].Rule != "TestEicar" {
		t.Errorf("Rule = %q, want %q", matches[0].Rule, "TestEicar")
	}
}

func TestYARAScanFileNoMatch(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	writeYARARule(t, dir)

	logger, _ := zap.NewDevelopment()
	engine, err := NewYARAEngine(dir, 50, 2, logger)
	if err != nil {
		t.Fatalf("NewYARAEngine: %v", err)
	}
	defer engine.Stop()

	clean := filepath.Join(t.TempDir(), "clean.txt")
	os.WriteFile(clean, []byte("hello world, nothing suspicious here"), 0o644)

	matches, err := engine.ScanFile(context.Background(), clean)
	if err != nil {
		t.Fatalf("ScanFile: %v", err)
	}
	if len(matches) != 0 {
		t.Errorf("ScanFile returned %d matches for clean file, want 0", len(matches))
	}
}

func TestYARAScanFileSizeLimit(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	writeYARARule(t, dir)

	logger, _ := zap.NewDevelopment()
	engine, err := NewYARAEngine(dir, 1, 1, logger) // 1 MB max
	if err != nil {
		t.Fatalf("NewYARAEngine: %v", err)
	}
	defer engine.Stop()

	bigFile := filepath.Join(t.TempDir(), "big.bin")
	os.WriteFile(bigFile, []byte(strings.Repeat("A", 2*1024*1024)), 0o644) // 2 MB

	_, err = engine.ScanFile(context.Background(), bigFile)
	if err == nil {
		t.Fatal("expected error for oversized file, got nil")
	}
}

func TestYARAScanBytes(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	writeYARARule(t, dir)

	logger, _ := zap.NewDevelopment()
	engine, err := NewYARAEngine(dir, 50, 2, logger)
	if err != nil {
		t.Fatalf("NewYARAEngine: %v", err)
	}
	defer engine.Stop()

	data := []byte("prefix EICAR-STANDARD-ANTIVIRUS-TEST-FILE suffix")
	matches, err := engine.ScanBytes(context.Background(), data)
	if err != nil {
		t.Fatalf("ScanBytes: %v", err)
	}
	if len(matches) == 0 {
		t.Fatal("ScanBytes returned 0 matches")
	}
}
