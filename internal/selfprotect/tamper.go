package selfprotect

import (
	"context"
	"fmt"
	"path/filepath"

	"github.com/fsnotify/fsnotify"
	"go.uber.org/zap"
)

// TamperDetector monitors protected agent files for unauthorized
// modifications using filesystem notifications.
type TamperDetector struct {
	protectedPaths []string
	logger         *zap.Logger
	protected      map[string]bool
}

// NewTamperDetector creates a detector that watches the given paths for
// tampering (modification, deletion, permission or ownership changes).
func NewTamperDetector(paths []string, logger *zap.Logger) *TamperDetector {
	pm := make(map[string]bool, len(paths))
	for _, p := range paths {
		abs, err := filepath.Abs(p)
		if err != nil {
			abs = p
		}
		pm[abs] = true
	}
	return &TamperDetector{
		protectedPaths: paths,
		logger:         logger,
		protected:      pm,
	}
}

// Start begins filesystem monitoring for all protected paths. It blocks
// until ctx is cancelled and detects: file modification, deletion,
// permission changes, and ownership changes.
func (td *TamperDetector) Start(ctx context.Context) error {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return fmt.Errorf("tamper: create watcher: %w", err)
	}
	defer watcher.Close()

	dirs := make(map[string]bool)
	for _, path := range td.protectedPaths {
		if err := watcher.Add(path); err != nil {
			td.logger.Warn("tamper: cannot watch path directly",
				zap.String("path", path), zap.Error(err))
		}
		dir := filepath.Dir(path)
		if !dirs[dir] {
			if err := watcher.Add(dir); err != nil {
				td.logger.Warn("tamper: cannot watch parent dir",
					zap.String("dir", dir), zap.Error(err))
			}
			dirs[dir] = true
		}
	}

	td.logger.Info("tamper detector started",
		zap.Int("protected_paths", len(td.protectedPaths)),
	)

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case event, ok := <-watcher.Events:
			if !ok {
				return nil
			}
			td.handleEvent(event)
		case err, ok := <-watcher.Errors:
			if !ok {
				return nil
			}
			td.logger.Error("tamper: watcher error", zap.Error(err))
		}
	}
}

// SetImmutable marks a file as immutable using platform-specific mechanisms
// (chattr +i on Linux, SF_IMMUTABLE on macOS, read-only DACL on Windows).
func (td *TamperDetector) SetImmutable(path string) error {
	return setImmutableFlag(path)
}

// IsImmutable reports whether the file at path currently has immutable
// protections applied.
func (td *TamperDetector) IsImmutable(path string) bool {
	return isImmutableFlag(path)
}

func (td *TamperDetector) handleEvent(event fsnotify.Event) {
	abs, err := filepath.Abs(event.Name)
	if err != nil {
		abs = event.Name
	}
	if !td.protected[abs] {
		return
	}

	fields := []zap.Field{
		zap.String("path", abs),
		zap.String("operation", event.Op.String()),
	}

	switch {
	case event.Op.Has(fsnotify.Remove) || event.Op.Has(fsnotify.Rename):
		td.logger.Error("tamper: protected file removed/renamed", fields...)
	case event.Op.Has(fsnotify.Write):
		td.logger.Error("tamper: protected file modified", fields...)
	case event.Op.Has(fsnotify.Chmod):
		td.logger.Warn("tamper: protected file permissions changed", fields...)
	}
}
