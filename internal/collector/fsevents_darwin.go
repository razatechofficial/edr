//go:build darwin

package collector

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/razatechofficial/edr/internal/schema"
)

type fseFileState struct {
	mod time.Time
	sz  int64
}

// FSEventsFallbackSource is a lightweight polling fallback used when ESF cannot initialize.
// It is intentionally bounded and best-effort to preserve file telemetry continuity.
type FSEventsFallbackSource struct {
	endpointID string
	hostname   string
	paths      []string
	seen       map[string]fseFileState
}

func NewFSEventsFallbackSource(endpointID, hostname string, paths []string) *FSEventsFallbackSource {
	if hostname == "" {
		hostname, _ = os.Hostname()
	}
	if len(paths) == 0 {
		paths = []string{"/Library/LaunchDaemons", "/Library/LaunchAgents", "/private/tmp"}
	}
	return &FSEventsFallbackSource{
		endpointID: endpointID,
		hostname:   hostname,
		paths:      paths,
		seen:       make(map[string]fseFileState, 2048),
	}
}

func (f *FSEventsFallbackSource) Snapshot() []Telemetry {
	now := time.Now().UTC()
	cur := make(map[string]fseFileState, len(f.seen))
	out := make([]Telemetry, 0, 64)

	for _, root := range f.paths {
		root = strings.TrimSpace(root)
		if root == "" {
			continue
		}
		_ = filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
			if err != nil || d == nil {
				return nil
			}
			if d.IsDir() {
				return nil
			}
			info, err := d.Info()
			if err != nil {
				return nil
			}
			st := fseFileState{mod: info.ModTime(), sz: info.Size()}
			cur[path] = st
			prev, ok := f.seen[path]
			if !ok {
				out = append(out, Telemetry{File: f.newFileEvent(now, path, "fsevents_fallback_create", 0)})
				return nil
			}
			if !prev.mod.Equal(st.mod) || prev.sz != st.sz {
				bw := uint64(0)
				if st.sz > prev.sz {
					bw = uint64(st.sz - prev.sz)
				}
				out = append(out, Telemetry{File: f.newFileEvent(now, path, "fsevents_fallback_modify", bw)})
			}
			return nil
		})
	}
	for p := range f.seen {
		if _, ok := cur[p]; !ok {
			out = append(out, Telemetry{File: f.newFileEvent(now, p, "fsevents_fallback_delete", 0)})
		}
	}
	f.seen = cur
	return out
}

func (f *FSEventsFallbackSource) newFileEvent(ts time.Time, path, op string, bytes uint64) *schema.FileEvent {
	return &schema.FileEvent{
		BaseEvent: schema.BaseEvent{
			SchemaVersion: schema.SchemaVersionV1,
			EventType:     schema.EventFile,
			EndpointID:    f.endpointID,
			Timestamp:     ts,
			Hostname:      f.hostname,
			OS:            runtime.GOOS,
		},
		Path:         path,
		Operation:    op,
		BytesWritten: bytes,
	}
}

func (f *FSEventsFallbackSource) Run(ctx context.Context, sink *StreamingSink) error {
	if sink == nil {
		return nil
	}
	t := time.NewTicker(5 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
			for _, tel := range f.Snapshot() {
				sink.Send(ctx, tel)
			}
		}
	}
}
