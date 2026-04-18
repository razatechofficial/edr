package collector

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"runtime"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/razatechofficial/edr/internal/schema"
)

// FileCollector monitors configured directories for file system changes using
// fsnotify (inotify on Linux, FSEvents on macOS, ReadDirectoryChangesW on Windows).
// Accumulated events are returned on each Collect call and the buffer is drained.
type FileCollector struct {
	endpointID string
	watchPaths []string
	watcher    *fsnotify.Watcher
	hostname   string

	mu     sync.Mutex
	events []schema.FileEvent
	done   chan struct{}
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
		out := []string{"/etc", "/usr/local/bin", "/tmp"}
		if home != "" {
			out = append(out, home)
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
// If paths is empty, DefaultFIMPaths() are used.
func NewFileCollector(endpointID string, paths []string) (*FileCollector, error) {
	if len(paths) == 0 {
		paths = DefaultFIMPaths()
	}

	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, err
	}

	hostname, _ := os.Hostname()

	fc := &FileCollector{
		endpointID: endpointID,
		watchPaths: paths,
		watcher:    watcher,
		hostname:   hostname,
		done:       make(chan struct{}),
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
	fc.events = nil
	fc.mu.Unlock()

	out := make([]Telemetry, 0, len(batch))
	for i := range batch {
		out = append(out, Telemetry{File: &batch[i]})
	}
	return out, nil
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

	fc.mu.Lock()
	fc.events = append(fc.events, fe)
	fc.mu.Unlock()
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
