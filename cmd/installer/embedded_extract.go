package main

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
)

func extractFSToDisk(src fs.FS, dstRoot string) error {
	return fs.WalkDir(src, ".", func(rel string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if rel == "." {
			return os.MkdirAll(dstRoot, 0755)
		}
		out := filepath.Join(dstRoot, filepath.FromSlash(rel))
		if d.IsDir() {
			return os.MkdirAll(out, 0755)
		}
		data, err := fs.ReadFile(src, rel)
		if err != nil {
			return err
		}
		if err := os.MkdirAll(filepath.Dir(out), 0755); err != nil {
			return err
		}
		return os.WriteFile(out, data, 0644)
	})
}

func extractEmbeddedInstallerAssets(root fs.FS, paths installPaths) error {
	// //go:embed all:bundle maps paths as bundle/models, bundle/rules, ... (see embedded_assets_bundle.go).
	bundleFS, err := fs.Sub(root, "bundle")
	if err != nil {
		return fmt.Errorf("embedded fs bundle: %w", err)
	}
	modelsFS, err := fs.Sub(bundleFS, "models")
	if err != nil {
		return fmt.Errorf("embedded fs models: %w", err)
	}
	rulesFS, err := fs.Sub(bundleFS, "rules")
	if err != nil {
		return fmt.Errorf("embedded fs rules: %w", err)
	}
	dstModels := filepath.Join(paths.dataDir, "models")
	if err := extractFSToDisk(modelsFS, dstModels); err != nil {
		return fmt.Errorf("extract models: %w", err)
	}
	if err := extractFSToDisk(rulesFS, paths.rulesDir); err != nil {
		return fmt.Errorf("extract rules: %w", err)
	}
	// Optional: edr-agent + edrctl staged for true single-file distribution (see Makefile build-installer-embedded).
	if binFS, err := fs.Sub(bundleFS, "bin"); err == nil {
		dstBin := filepath.Join(paths.dataDir, "installer", "bin")
		if err := extractFSToDisk(binFS, dstBin); err != nil {
			return fmt.Errorf("extract embedded bin: %w", err)
		}
	}
	return nil
}
