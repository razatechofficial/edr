package collector

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/razatechofficial/edr/internal/config"
	"github.com/razatechofficial/edr/internal/forensics"
	"github.com/razatechofficial/edr/internal/schema"
)

// FileCollector monitors configured directories for file system changes using
// fsnotify (inotify on Linux, FSEvents on macOS, ReadDirectoryChangesW on Windows).
// Accumulated events are returned on each Collect call and the buffer is drained.
type FileCollector struct {
	endpointID     string
	watchPaths     []string
	ignorePatterns []string
	watcher        *fsnotify.Watcher
	hostname   string
	fimDiff    *forensics.FIMDiffCache

	mu     sync.Mutex
	events []schema.FileEvent
	extras []Telemetry
	done   chan struct{}

	emitted atomic.Uint64
	dropped atomic.Uint64
}

// DefaultFIMPaths returns platform-appropriate paths to watch for file integrity.
// fsnotify does not recurse: watching /Users or C:\Users does not deliver events for
// files created under /Users/<name>/ or C:\Users\<name>\. Include the current user's
// home directory explicitly so typical user paths are covered.
func DefaultFIMPaths() []string {
	home, _ := os.UserHomeDir()
	switch runtime.GOOS {
	case "linux":
		out := []string{"/etc", "/usr/bin", "/usr/sbin", "/tmp", "/var/tmp"}
		if home != "" {
			out = append(out, home)
		}
		return out
	case "darwin":
		out := []string{
			"/etc", "/usr/local/bin", "/tmp",
			"/Library/LaunchAgents", "/Library/LaunchDaemons",
			"/Library/Keychains",
			"/Library/Application Support/com.apple.TCC",
		}
		if home != "" {
			out = append(out,
				home,
				filepath.Join(home, "Library/LaunchAgents"),
				filepath.Join(home, "Library/Keychains"),
				filepath.Join(home, "Library/Application Support/com.apple.TCC"),
			)
		}
		return out
	case "windows":
		out := []string{`C:\Windows\System32`, `C:\Windows\Temp`}
		if home != "" {
			out = append(out, home)
		}
		return out
	default:
		if home != "" {
			return []string{"/tmp", home}
		}
		return []string{"/tmp"}
	}
}

// NewFileCollector creates a file integrity monitor watching the given paths.
// When paths is empty, ResolveFIMPaths(cfg) is used (standard FIM preset by default).
func NewFileCollector(endpointID string, paths []string, cfg config.Config) (*FileCollector, error) {
	if len(paths) == 0 {
		paths = ResolveFIMPaths(cfg)
	}
	ignorePatterns := ResolveFIMIgnorePatterns(cfg)

	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, err
	}

	hostname, _ := os.Hostname()

	fc := &FileCollector{
		endpointID:     endpointID,
		watchPaths:     paths,
		ignorePatterns: ignorePatterns,
		watcher:        watcher,
		hostname:   hostname,
		done:       make(chan struct{}),
		fimDiff: forensics.NewFIMDiffCache(forensics.FIMDiffConfig{
			Enabled:      cfg.Response.Forensics.FIMDiffEnabled,
			MaxFileBytes: cfg.Response.Forensics.FIMDiffMaxFileBytes,
			PathGlobs:    cfg.Response.Forensics.FIMDiffPathGlobs,
		}),
	}

	for _, p := range paths {
		if err := watcher.Add(p); err != nil {
			// Non-fatal: some paths may not exist yet.
			continue
		}
	}

	go fc.watchLoop()
	return fc, nil
}

func (fc *FileCollector) Name() string { return "file" }

func (fc *FileCollector) Collect(_ context.Context) ([]Telemetry, error) {
	fc.mu.Lock()
	batch := fc.events
	extras := fc.extras
	fc.events = nil
	fc.extras = nil
	fc.mu.Unlock()

	out := make([]Telemetry, 0, len(batch)+len(extras))
	for i := range batch {
		out = append(out, Telemetry{File: &batch[i]})
	}
	out = append(out, extras...)
	fc.emitted.Add(uint64(len(out)))
	return out, nil
}

// ExportMonitoringHealth surfaces fsnotify watcher stats.
func (fc *FileCollector) ExportMonitoringHealth() map[string]any {
	src := MonitoringSource{
		Name:    "file",
		OS:      runtime.GOOS,
		Source:  "fsnotify",
		Status:  "healthy",
		EPSOut:  fc.emitted.Load(),
		Dropped: fc.dropped.Load(),
	}
	if fc.watcher == nil {
		src.Status = "unavailable"
		src.LastError = "fsnotify watcher not initialized"
	}
	out := src.ToMap()
	if fc.fimDiff != nil {
		out["fim_diff_files_tracked"] = fc.fimDiff.TrackedFiles()
		out["fim_diff_emits_total"] = fc.fimDiff.EmitsTotal()
	}
	return out
}

func (fc *FileCollector) Close() error {
	close(fc.done)
	return fc.watcher.Close()
}

func (fc *FileCollector) watchLoop() {
	for {
		select {
		case <-fc.done:
			return
		case event, ok := <-fc.watcher.Events:
			if !ok {
				return
			}
			fc.handleFSEvent(event)
		case _, ok := <-fc.watcher.Errors:
			if !ok {
				return
			}
		}
	}
}

func (fc *FileCollector) handleFSEvent(event fsnotify.Event) {
	if shouldIgnoreFIMEvent(event.Name, fc.ignorePatterns) {
		return
	}
	op := mapFSOperation(event.Op)
	if op == "" {
		return
	}

	fe := schema.FileEvent{
		BaseEvent: schema.BaseEvent{
			SchemaVersion: schema.SchemaVersionV1,
			EventType:     schema.EventFile,
			EndpointID:    fc.endpointID,
			Timestamp:     time.Now().UTC(),
			Hostname:      fc.hostname,
			OS:            runtime.GOOS,
		},
		Path:      event.Name,
		Operation: op,
	}

	if event.Op.Has(fsnotify.Create) || event.Op.Has(fsnotify.Write) {
		if h, err := quickHash(event.Name); err == nil {
			fe.Hash = h
		}
	}
	if fc.fimDiff != nil && event.Op.Has(fsnotify.Write) {
		path := event.Name
		if b64, err := fc.fimDiff.DiffOnModify(path, func() ([]byte, error) {
			return os.ReadFile(path)
		}); err == nil && b64 != "" {
			fe.FIMDiffUnified = b64
		}
	}

	fc.mu.Lock()
	fc.events = append(fc.events, fe)
	fc.emitDarwinFIMEnrichment(event, fe)
	fc.mu.Unlock()
}

func (fc *FileCollector) emitDarwinFIMEnrichment(event fsnotify.Event, fe schema.FileEvent) {
	if runtime.GOOS != "darwin" {
		return
	}
	lp := strings.ToLower(fe.Path)
	if strings.Contains(lp, "tcc.db") && (event.Op.Has(fsnotify.Write) || event.Op.Has(fsnotify.Create)) {
		fc.extras = append(fc.extras, Telemetry{
			Privacy: &schema.PrivacyEvent{
				BaseEvent: schema.BaseEvent{
					SchemaVersion: schema.SchemaVersionV1,
					EventType:     schema.EventFile,
					EndpointID:    fc.endpointID,
					Timestamp:     fe.Timestamp,
					Hostname:      fc.hostname,
					OS:            runtime.GOOS,
				},
				Operation: "tcc_db_write",
			},
		})
	}
	if strings.HasSuffix(lp, ".keychain") || strings.HasSuffix(lp, ".keychain-db") {
		fc.extras = append(fc.extras, Telemetry{
			Credential: &schema.CredentialAccessEvent{
				BaseEvent: schema.BaseEvent{
					SchemaVersion: schema.SchemaVersionV1,
					EventType:     schema.EventFile,
					EndpointID:    fc.endpointID,
					Timestamp:     fe.Timestamp,
					Hostname:      fc.hostname,
					OS:            runtime.GOOS,
				},
				Technique:  "keychain_access",
				TargetPath: fe.Path,
				Severity:   "P1",
			},
		})
	}
}

func mapFSOperation(op fsnotify.Op) string {
	switch {
	case op.Has(fsnotify.Create):
		return "create"
	case op.Has(fsnotify.Write):
		return "modify"
	case op.Has(fsnotify.Remove):
		return "delete"
	case op.Has(fsnotify.Rename):
		return "rename"
	case op.Has(fsnotify.Chmod):
		return "chmod"
	default:
		return ""
	}
}

func quickHash(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, io.LimitReader(f, 10<<20)); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
