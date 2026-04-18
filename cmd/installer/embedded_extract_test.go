package main

import (
	"io/fs"
	"path/filepath"
	"testing"
	"testing/fstest"
)

// The //go:embed all:bundle tree exposes paths as bundle/models/..., not models/...
func TestExtractEmbeddedUsesBundlePrefix(t *testing.T) {
	t.Parallel()
	m := fstest.MapFS{
		"bundle/models/x.onnx": &fstest.MapFile{Data: []byte("m"), Mode: 0644},
		"bundle/rules/a.yaml":  &fstest.MapFile{Data: []byte("r"), Mode: 0644},
		"bundle/bin/edr-agent": &fstest.MapFile{Data: []byte("#!/bin/sh\n"), Mode: 0755},
	}
	bundleFS, err := fs.Sub(m, "bundle")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fs.Sub(bundleFS, "models"); err != nil {
		t.Fatalf("expected bundle/models: %v", err)
	}
}

func TestExtractEmbeddedInstallerAssets_smoke(t *testing.T) {
	t.Parallel()
	m := fstest.MapFS{
		"bundle/models/x.onnx": &fstest.MapFile{Data: []byte("m"), Mode: 0644},
		"bundle/rules/a.yaml":  &fstest.MapFile{Data: []byte("r"), Mode: 0644},
		"bundle/bin/edr-agent": &fstest.MapFile{Data: []byte("x"), Mode: 0755},
	}
	tmp := t.TempDir()
	paths := installPaths{
		dataDir:       filepath.Join(tmp, "data"),
		rulesDir:      filepath.Join(tmp, "data", "config", "rules"),
		quarantineDir: filepath.Join(tmp, "data", "quarantine"),
	}
	if err := extractEmbeddedInstallerAssets(m, paths); err != nil {
		t.Fatal(err)
	}
}
