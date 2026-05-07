//go:build darwin

package collector

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/xml"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/razatechofficial/edr/internal/schema"
)

// LaunchdPlistSource enumerates LaunchAgents/LaunchDaemons plists at startup
// and on a configurable interval. Each plist is parsed for the standard
// `Label`, `ProgramArguments`, and `RunAtLoad` keys; new or modified entries
// are emitted as ProcessEvent telemetry tagged "launchd_persistence" so
// detection rules can flag freshly installed login items.
//
// We deliberately read the file rather than spawning `launchctl list`:
//   - launchctl is per-session, requiring root + console-user impersonation
//     to enumerate every domain;
//   - the on-disk plist set is the authoritative persistence surface used
//     by adversaries who add startup hooks.
type LaunchdPlistSource struct {
	endpointID string
	hostname   string
	roots      []string

	mu       sync.Mutex // guards: known
	known    map[string]plistFingerprint

	scans   atomic.Uint64
	emitted atomic.Uint64
	errs    atomic.Pointer[string]
}

type plistFingerprint struct {
	modtime time.Time
	size    int64
	sha256  string
}

func plistContentSHA256(path string) string {
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// NewLaunchdPlistSource builds a source that scans the standard plist roots:
// /Library/LaunchAgents, /Library/LaunchDaemons, /System/Library/LaunchAgents,
// /System/Library/LaunchDaemons, and ~/Library/LaunchAgents for the running
// user. extraRoots is appended verbatim.
func NewLaunchdPlistSource(endpointID, hostname string, extraRoots ...string) *LaunchdPlistSource {
	if hostname == "" {
		if h, err := os.Hostname(); err == nil {
			hostname = h
		} else {
			hostname = "unknown"
		}
	}
	roots := []string{
		"/Library/LaunchAgents",
		"/Library/LaunchDaemons",
		"/System/Library/LaunchAgents",
		"/System/Library/LaunchDaemons",
	}
	if home, err := os.UserHomeDir(); err == nil && home != "" {
		roots = append(roots, filepath.Join(home, "Library/LaunchAgents"))
	}
	roots = append(roots, extraRoots...)
	return &LaunchdPlistSource{
		endpointID: endpointID,
		hostname:   hostname,
		roots:      roots,
		known:      make(map[string]plistFingerprint),
	}
}

// setRoots replaces the configured roots; intended for tests.
func (l *LaunchdPlistSource) setRoots(roots ...string) {
	l.mu.Lock()
	l.roots = append(l.roots[:0], roots...)
	l.known = make(map[string]plistFingerprint)
	l.mu.Unlock()
}

// Snapshot scans every root once and emits Telemetry for entries that are new
// or whose modtime/size has changed since the previous call. Removed entries
// are reaped from the in-memory cache so memory remains bounded.
func (l *LaunchdPlistSource) Snapshot(ctx context.Context) ([]Telemetry, error) {
	l.scans.Add(1)
	out := make([]Telemetry, 0, 16)
	current := make(map[string]plistFingerprint, 64)

	for _, root := range l.roots {
		if ctx.Err() != nil {
			return out, ctx.Err()
		}
		entries, err := os.ReadDir(root)
		if err != nil {
			if !errors.Is(err, fs.ErrNotExist) {
				l.recordError(err)
			}
			continue
		}
		for _, e := range entries {
			if !strings.HasSuffix(e.Name(), ".plist") {
				continue
			}
			path := filepath.Join(root, e.Name())
			info, err := e.Info()
			if err != nil {
				continue
			}
			fp := plistFingerprint{
				modtime: info.ModTime(),
				size:    info.Size(),
				sha256:  plistContentSHA256(path),
			}
			current[path] = fp

			l.mu.Lock()
			prev, seen := l.known[path]
			l.mu.Unlock()
			if seen && prev == fp {
				continue
			}
			label, program := readPlistKeys(path)
			pe := &schema.ProcessEvent{
				BaseEvent: schema.BaseEvent{
					SchemaVersion: schema.SchemaVersionV1,
					EventType:     schema.EventProcess,
					EndpointID:    l.endpointID,
					Timestamp:     time.Now().UTC(),
					Hostname:      l.hostname,
					OS:            runtime.GOOS,
				},
				ProcessName: "launchd_persistence",
				ProcessPath: program,
				CommandLine: label,
				ImageSHA256: fp.sha256,
			}
			out = append(out, Telemetry{Process: pe})
			l.emitted.Add(1)
		}
	}

	l.mu.Lock()
	l.known = current
	l.mu.Unlock()
	return out, nil
}

// readPlistKeys does a minimal, allocation-light parse of a launchd plist's
// `Label` and `ProgramArguments` fields. It does not validate the plist
// schema; missing values yield empty strings.
func readPlistKeys(path string) (label, program string) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", ""
	}
	dec := xml.NewDecoder(strings.NewReader(string(data)))
	type token struct {
		key  string
		text string
	}
	var (
		curKey   string
		inString bool
		args     []string
		inArgs   bool
	)
	for {
		tok, err := dec.Token()
		if err != nil {
			break
		}
		switch t := tok.(type) {
		case xml.StartElement:
			switch t.Name.Local {
			case "key":
				inString = false
				curKey = ""
			case "string":
				inString = true
			case "array":
				if curKey == "ProgramArguments" {
					inArgs = true
					args = nil
				}
			}
		case xml.EndElement:
			if t.Name.Local == "array" && inArgs {
				inArgs = false
				program = strings.Join(args, " ")
			}
		case xml.CharData:
			if inString {
				if curKey == "Label" {
					label = strings.TrimSpace(string(t))
				} else if inArgs {
					if v := strings.TrimSpace(string(t)); v != "" {
						args = append(args, v)
					}
				} else if curKey == "Program" && program == "" {
					program = strings.TrimSpace(string(t))
				}
				inString = false
				curKey = ""
			} else if curKey == "" {
				curKey = strings.TrimSpace(string(t))
			}
		}
	}
	return label, program
}

// ExportMonitoringHealth implements the per-source health interface.
func (l *LaunchdPlistSource) ExportMonitoringHealth() map[string]any {
	src := MonitoringSource{
		Name:   "persistence",
		OS:     "darwin",
		Source: "launchd-plist",
		Status: "healthy",
		EPSIn:  l.scans.Load(),
		EPSOut: l.emitted.Load(),
	}
	if errPtr := l.errs.Load(); errPtr != nil && *errPtr != "" {
		src.LastError = *errPtr
		src.Status = "degraded"
	}
	return src.ToMap()
}

func (l *LaunchdPlistSource) recordError(err error) {
	if err == nil {
		return
	}
	msg := err.Error()
	l.errs.Store(&msg)
}
