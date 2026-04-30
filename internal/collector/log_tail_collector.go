package collector

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/razatechofficial/edr/internal/config"
)

const logTailMaxChunk = 256 * 1024

// LogTailCollector tails configured text files (G-L4-BREADTH curated sources).
// Emits no primary telemetry in this revision; exposes monitoring_health only.
type LogTailCollector struct {
	cfg        config.Config
	paths      []string
	mu         sync.Mutex
	lastErr    string
	readBytes  atomic.Uint64
	tick       atomic.Uint64
	pathStatus map[string]string
}

// NewLogTailCollector returns nil when no paths configured.
func NewLogTailCollector(cfg config.Config) *LogTailCollector {
	paths := normalizeLogTailPaths(cfg.Monitoring.AdditionalLogTailPaths)
	if len(paths) == 0 {
		return nil
	}
	return &LogTailCollector{
		cfg:        cfg,
		paths:      paths,
		pathStatus: make(map[string]string, len(paths)),
	}
}

func normalizeLogTailPaths(in []string) []string {
	var out []string
	seen := map[string]struct{}{}
	for _, p := range in {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		if _, ok := seen[p]; ok {
			continue
		}
		seen[p] = struct{}{}
		out = append(out, p)
	}
	return out
}

func (l *LogTailCollector) Name() string { return "log_tail" }

func (l *LogTailCollector) Collect(ctx context.Context) ([]Telemetry, error) {
	l.tick.Add(1)
	var errs []string
	for _, p := range l.paths {
		if ctx.Err() != nil {
			break
		}
		n, err := l.drainTail(ctx, p)
		if err != nil {
			l.mu.Lock()
			l.pathStatus[p] = "error: " + err.Error()
			l.mu.Unlock()
			errs = append(errs, p+": "+err.Error())
			continue
		}
		l.readBytes.Add(n)
		l.mu.Lock()
		l.pathStatus[p] = "ok"
		l.mu.Unlock()
	}
	l.mu.Lock()
	if len(errs) > 0 {
		l.lastErr = strings.Join(errs, "; ")
	} else {
		l.lastErr = ""
	}
	l.mu.Unlock()
	return nil, nil
}

func (l *LogTailCollector) drainTail(ctx context.Context, path string) (uint64, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return 0, err
	}
	if fi.IsDir() {
		return 0, fmt.Errorf("is directory")
	}
	sz := fi.Size()
	off := int64(0)
	if sz > logTailMaxChunk {
		off = sz - logTailMaxChunk
	}
	f, err := os.Open(filepath.Clean(path))
	if err != nil {
		return 0, err
	}
	defer f.Close()
	if off > 0 {
		if _, err := f.Seek(off, io.SeekStart); err != nil {
			return 0, err
		}
	}
	buf, err := io.ReadAll(io.LimitReader(f, logTailMaxChunk))
	if err != nil {
		return 0, err
	}
	return uint64(len(buf)), nil
}

func (l *LogTailCollector) ExportMonitoringHealth() map[string]any {
	st := "healthy"
	l.mu.Lock()
	errStr := l.lastErr
	statusCopy := make(map[string]string, len(l.pathStatus))
	for k, v := range l.pathStatus {
		statusCopy[k] = v
	}
	l.mu.Unlock()
	if errStr != "" {
		st = "degraded"
	}
	lastErr := errStr
	src := MonitoringSource{
		Name:      "log_tail",
		OS:        runtime.GOOS,
		Source:    "file_tail",
		Status:    st,
		EPSOut:    l.tick.Load(),
		LastError: lastErr,
	}.ToMap()
	src["bytes_tail_read_total"] = float64(l.readBytes.Load())
	src["paths_configured"] = float64(len(l.paths))
	src["path_status"] = statusCopy
	return src
}
