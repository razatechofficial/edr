package ml

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"go.uber.org/zap"
)

// AutoUpdater periodically checks a local directory (or HTTP URL when network
// is available) for new model versions and hot-swaps them into the running
// engine. For airgap deployments it watches a local directory only.
type AutoUpdater struct {
	engine   *Engine
	dir      string
	interval time.Duration
	logger   *zap.Logger
}

// NewAutoUpdater creates an updater that polls dir for manifest.json changes.
func NewAutoUpdater(engine *Engine, modelsDir string, intervalHours int, logger *zap.Logger) *AutoUpdater {
	if intervalHours <= 0 {
		intervalHours = 1
	}
	return &AutoUpdater{
		engine:   engine,
		dir:      modelsDir,
		interval: time.Duration(intervalHours) * time.Hour,
		logger:   logger,
	}
}

// Run polls for model updates until the context is cancelled.
func (u *AutoUpdater) Run(ctx context.Context) {
	u.logger.Info("ml auto-updater started",
		zap.String("models_dir", u.dir),
		zap.Duration("interval", u.interval))

	ticker := time.NewTicker(u.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			u.logger.Info("ml auto-updater stopped")
			return
		case <-ticker.C:
			if err := u.checkAndUpdate(); err != nil {
				u.logger.Warn("ml auto-update check failed", zap.Error(err))
			}
		}
	}
}

func (u *AutoUpdater) checkAndUpdate() error {
	manifestPath := filepath.Join(u.dir, "manifest.json")
	data, err := os.ReadFile(manifestPath)
	if err != nil {
		return fmt.Errorf("read manifest: %w", err)
	}

	var manifest Manifest
	if err := json.Unmarshal(data, &manifest); err != nil {
		return fmt.Errorf("parse manifest: %w", err)
	}

	mgr := u.engine.Models()
	for _, entry := range manifest.Models {
		current := mgr.ActiveVersion(entry.Name)
		if current != nil && current.Version == entry.Version && current.SHA256 == entry.SHA256 {
			continue
		}

		modelPath := filepath.Join(u.dir, entry.File)
		if _, statErr := os.Stat(modelPath); statErr != nil {
			continue
		}

		if entry.SHA256 != "" {
			hash, hashErr := fileHashSHA256(modelPath)
			if hashErr != nil || hash != entry.SHA256 {
				u.logger.Warn("model hash mismatch, skipping",
					zap.String("model", entry.Name),
					zap.String("expected", entry.SHA256),
					zap.String("got", hash))
				continue
			}
		}

		modelData, err := os.ReadFile(modelPath)
		if err != nil {
			u.logger.Warn("read model file failed", zap.String("model", entry.Name), zap.Error(err))
			continue
		}

		var sig []byte
		sigPath := modelPath + ".sig"
		if sigData, sigErr := os.ReadFile(sigPath); sigErr == nil {
			sig = sigData
		}

		oldVersion := "none"
		if current != nil {
			oldVersion = current.Version
		}

		if err := mgr.HotSwap(entry.Name, modelData, sig); err != nil {
			u.logger.Warn("hot-swap failed", zap.String("model", entry.Name), zap.Error(err))
			continue
		}

		u.logger.Info("model hot-swapped",
			zap.String("model", entry.Name),
			zap.String("old_version", oldVersion),
			zap.String("new_version", entry.Version))
	}

	if err := mgr.LoadManifest(u.dir); err != nil {
		u.logger.Warn("reload manifest after update", zap.Error(err))
	}
	return nil
}

func fileHashSHA256(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:]), nil
}
