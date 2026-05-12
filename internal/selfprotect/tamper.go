package selfprotect

import (
	"context"
	"fmt"
	"path/filepath"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"
	"go.uber.org/zap"
)

// TamperResponse describes what the detector did in response to a
// tampering event. Emitted via the responseHook so a forwarder can
// surface the action as a high-severity alert.
type TamperResponse struct {
	Path      string    `json:"path"`
	Operation string    `json:"operation"`
	KillerPID int       `json:"killer_pid,omitempty"`
	Action    string    `json:"action"`
	Timestamp time.Time `json:"timestamp"`
	Restored  bool      `json:"restored,omitempty"`
	Error     string    `json:"error,omitempty"`
}

// TamperResponseHook receives a structured response event after every
// tamper-handling pass. It is called synchronously from the watcher
// goroutine so the implementation must not block.
type TamperResponseHook func(TamperResponse)

// TamperDetector monitors protected agent files for unauthorized
// modifications using filesystem notifications. P1-20: on detection
// the detector identifies the writing process via platform-specific
// hooks (auditd / open-file enumeration on Linux, minifilter PID on
// Windows, ESF audit token on macOS), kills it, and emits a structured
// response event so the response shows up alongside the tamper alert.
type TamperDetector struct {
	protectedPaths []string
	logger         *zap.Logger
	protected      map[string]bool

	mu          sync.RWMutex
	responseHook TamperResponseHook
	restoreFn    func(path string) error
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

// SetResponseHook installs a callback invoked after every tamper event
// is handled. Used by the agent runtime to forward the structured
// response as a high-severity alert.
func (td *TamperDetector) SetResponseHook(fn TamperResponseHook) {
	td.mu.Lock()
	td.responseHook = fn
	td.mu.Unlock()
}

// SetRestoreFn installs a callback that restores a protected file from
// the integrity backup. Decoupled from the detector so the package does
// not import selfprotect.IntegrityChecker directly.
func (td *TamperDetector) SetRestoreFn(fn func(path string) error) {
	td.mu.Lock()
	td.restoreFn = fn
	td.mu.Unlock()
}

func (td *TamperDetector) emitResponse(r TamperResponse) {
	td.mu.RLock()
	hook := td.responseHook
	td.mu.RUnlock()
	if hook == nil {
		return
	}
	hook(r)
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

	severity := "warn"
	switch {
	case event.Op.Has(fsnotify.Remove) || event.Op.Has(fsnotify.Rename):
		td.logger.Error("tamper: protected file removed/renamed", fields...)
		severity = "critical"
	case event.Op.Has(fsnotify.Write):
		td.logger.Error("tamper: protected file modified", fields...)
		severity = "critical"
	case event.Op.Has(fsnotify.Chmod):
		td.logger.Warn("tamper: protected file permissions changed", fields...)
		severity = "warn"
	default:
		return
	}

	resp := TamperResponse{
		Path:      abs,
		Operation: event.Op.String(),
		Action:    "detected",
		Timestamp: time.Now().UTC(),
	}

	// P1-20: attempt to identify the writing process and kill it. The
	// platform-specific findTamperingProcess implementation returns 0
	// when it cannot determine the responsible PID (the platform lacks
	// the audit hook, or the writer already exited). In that case we
	// still emit the response with action="detected" so the alert
	// surfaces.
	if severity == "critical" {
		if pid := findTamperingProcess(abs); pid > 0 {
			td.logger.Error("tamper: killing tampering process", zap.Int("pid", pid))
			if killErr := killProcess(pid); killErr != nil {
				resp.Action = "kill_failed"
				resp.Error = killErr.Error()
				resp.KillerPID = pid
				td.logger.Error("tamper: kill failed",
					zap.Int("pid", pid), zap.Error(killErr))
			} else {
				resp.Action = "process_killed"
				resp.KillerPID = pid
			}
		}

		td.mu.RLock()
		restore := td.restoreFn
		td.mu.RUnlock()
		if restore != nil {
			if rerr := restore(abs); rerr != nil {
				td.logger.Error("tamper: restore failed",
					zap.String("path", abs), zap.Error(rerr))
				if resp.Error == "" {
					resp.Error = rerr.Error()
				}
			} else {
				resp.Restored = true
				if resp.Action == "detected" {
					resp.Action = "restored"
				}
			}
		}
	}

	td.emitResponse(resp)
}
