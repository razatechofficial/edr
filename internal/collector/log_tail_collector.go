package collector

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/razatechofficial/edr/internal/config"
	"github.com/razatechofficial/edr/internal/schema"
)

const logTailMaxChunk = 256 * 1024

// logTailMaxLineBytes caps a single log line mapped to one FileEvent (enterprise tailers).
const logTailMaxLineBytes = 8 * 1024

// LogTailCollector tails configured text files (G-L4-BREADTH curated sources).
// Default mode is read-only drain for monitoring_health; file_events emits capped FileEvents.
type LogTailCollector struct {
	cfg        config.Config
	paths      []string
	endpointID string
	hostname   string

	mu         sync.Mutex
	lastErr    string
	readBytes  atomic.Uint64
	tick       atomic.Uint64
	pathStatus map[string]string
	dropped    atomic.Uint64 // rate-limited line drops (file_events mode)

	offsets   map[string]persistedLogOffset
	offsetsMu sync.Mutex

	rateWindow int64
	rateCount  int
	rateMu     sync.Mutex
}

// NewLogTailCollector returns nil when no paths configured.
func NewLogTailCollector(cfg config.Config) *LogTailCollector {
	paths := NormalizeAdditionalLogTailPaths(cfg.Monitoring.AdditionalLogTailPaths)
	if len(paths) == 0 {
		return nil
	}
	host, _ := os.Hostname()
	ep := strings.TrimSpace(cfg.Service.EndpointID)
	if ep == "" {
		ep = "unknown"
	}
	lt := &LogTailCollector{
		cfg:        cfg,
		paths:      paths,
		endpointID: ep,
		hostname:   host,
		pathStatus: make(map[string]string, len(paths)),
		offsets:    make(map[string]persistedLogOffset),
	}
	lt.loadOffsets()
	return lt
}

// LogTailPathsConfigured reports whether log breadth is configured (log_targets and/or additional_log_tail_paths).
func LogTailPathsConfigured(cfg config.Config) bool {
	return LogTargetsBreadthConfigured(cfg)
}

// NormalizeAdditionalLogTailPaths deduplicates non-empty monitoring.additional_log_tail_paths entries.
func NormalizeAdditionalLogTailPaths(in []string) []string {
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

func isLogTailFileEventsMode(cfg config.Config) bool {
	return strings.EqualFold(strings.TrimSpace(cfg.Monitoring.LogTailTelemetryMode), "file_events")
}

func (l *LogTailCollector) Name() string { return "log_tail" }

func (l *LogTailCollector) offsetsPath() string {
	dd := strings.TrimSpace(l.cfg.Agent.DataDir)
	if dd == "" {
		return ""
	}
	return filepath.Join(dd, "log_tail_offsets.json")
}

func (l *LogTailCollector) loadOffsets() {
	p := l.offsetsPath()
	if p == "" {
		return
	}
	data, err := os.ReadFile(p)
	if err != nil {
		return
	}
	m := loadPersistedLogOffsets(data)
	if m == nil {
		return
	}
	l.offsetsMu.Lock()
	for k, v := range m {
		l.offsets[k] = v
	}
	l.offsetsMu.Unlock()
}

func (l *LogTailCollector) persistOffsets() {
	p := l.offsetsPath()
	if p == "" {
		return
	}
	l.offsetsMu.Lock()
	data, err := json.Marshal(l.offsets)
	l.offsetsMu.Unlock()
	if err != nil {
		return
	}
	_ = os.WriteFile(p, data, 0o600)
}

func (l *LogTailCollector) allowFileEventEmit() bool {
	capN := l.cfg.Monitoring.StreamMaxEPS
	if capN <= 0 {
		return true
	}
	now := time.Now().Unix()
	l.rateMu.Lock()
	defer l.rateMu.Unlock()
	if now != l.rateWindow {
		l.rateWindow = now
		l.rateCount = 0
	}
	if l.rateCount >= capN {
		return false
	}
	l.rateCount++
	return true
}

func (l *LogTailCollector) Collect(ctx context.Context) ([]Telemetry, error) {
	l.tick.Add(1)
	var errs []string
	var out []Telemetry
	fileEv := isLogTailFileEventsMode(l.cfg)

	for _, p := range l.paths {
		if ctx.Err() != nil {
			break
		}
		if fileEv {
			evs, n, err := l.drainPathFileEvents(ctx, p)
			if err != nil {
				l.mu.Lock()
				l.pathStatus[p] = "error: " + err.Error()
				l.mu.Unlock()
				errs = append(errs, p+": "+err.Error())
				continue
			}
			l.readBytes.Add(n)
			out = append(out, evs...)
			l.mu.Lock()
			l.pathStatus[p] = "ok"
			l.mu.Unlock()
		} else {
			n, err := l.drainTailChunk(ctx, p)
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
	}
	if fileEv {
		l.persistOffsets()
	}
	l.mu.Lock()
	if len(errs) > 0 {
		l.lastErr = strings.Join(errs, "; ")
	} else {
		l.lastErr = ""
	}
	l.mu.Unlock()
	return out, nil
}

func (l *LogTailCollector) drainPathFileEvents(ctx context.Context, path string) ([]Telemetry, uint64, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return nil, 0, err
	}
	if fi.IsDir() {
		return nil, 0, fmt.Errorf("is directory")
	}
	dev, ino := fileTailIdentity(fi)
	l.offsetsMu.Lock()
	pos := l.offsets[path]
	l.offsetsMu.Unlock()
	off := pickLogReadOffset(pos, dev, ino, fi.Size())

	f, err := os.Open(filepath.Clean(path))
	if err != nil {
		return nil, 0, err
	}
	defer f.Close()
	if _, err := f.Seek(off, io.SeekStart); err != nil {
		return nil, 0, err
	}

	var out []Telemetry
	var bytesRead int64
	now := time.Now().UTC()
	r := bufio.NewReader(f)
	for {
		if ctx.Err() != nil {
			break
		}
		line, err := r.ReadString('\n')
		bytesRead += int64(len(line))
		if len(line) == 0 && err == io.EOF {
			break
		}
		trim := strings.TrimSuffix(line, "\n")
		trim = strings.TrimSuffix(trim, "\r")
		if trim != "" {
			if len(trim) > logTailMaxLineBytes {
				trim = trim[:logTailMaxLineBytes]
			}
			if !l.allowFileEventEmit() {
				l.dropped.Add(1)
			} else {
				ev := schema.FileEvent{
					BaseEvent: schema.BaseEvent{
						SchemaVersion: schema.SchemaVersionV1,
						EventType:     schema.EventFile,
						EndpointID:    l.endpointID,
						Timestamp:     now,
						Hostname:      l.hostname,
						OS:            runtime.GOOS,
					},
					Path:         path,
					Operation:    "log_tail_line",
					ActorPID:     0,
					BytesWritten: uint64(len(trim)),
				}
				out = append(out, Telemetry{File: &ev})
			}
		}
		if err != nil {
			if err == io.EOF {
				break
			}
			return out, uint64(bytesRead), err
		}
	}
	newOff := off + bytesRead
	l.offsetsMu.Lock()
	l.offsets[path] = persistedLogOffset{Dev: dev, Ino: ino, Off: newOff}
	l.offsetsMu.Unlock()
	return out, uint64(bytesRead), nil
}

func (l *LogTailCollector) drainTailChunk(ctx context.Context, path string) (uint64, error) {
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
	_ = ctx
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
	ltSrc := MonitoringSource{
		Name:      "log_tail",
		OS:        runtime.GOOS,
		Source:    "file_tail",
		Status:    st,
		EPSOut:    l.tick.Load(),
		LastError: lastErr,
		Dropped:   l.dropped.Load(),
	}
	if n := logTailTelemetryModeNotes(l.cfg.Monitoring.LogTailTelemetryMode); n != "" {
		ltSrc.Notes = n
	}
	src := ltSrc.ToMap()
	src["bytes_tail_read_total"] = float64(l.readBytes.Load())
	src["paths_configured"] = float64(len(l.paths))
	src["path_status"] = statusCopy
	return src
}

func logTailTelemetryModeNotes(mode string) string {
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case "", "none":
		return ""
	case "file_events":
		return "log_tail_telemetry_mode=file_events: per-line FileEvent emission active (cap=stream_max_eps, truncate=8KiB, offset-persistent when agent.data_dir set)"
	default:
		return "log_tail_telemetry_mode=" + strings.TrimSpace(mode) + ": unknown mode; collector read-only only"
	}
}
