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

// LogTargetsCollector collects logs from file, journald, command,
// and (on Windows) eventchannel targets with per-target monitoring_health rows.
type LogTargetsCollector struct {
	cfg        config.Config
	targets    []config.LogTarget
	endpointID string
	hostname   string

	mu      sync.Mutex
	states  []logTargetRuntime
	offsets map[string]persistedLogOffset

	readBytes atomic.Uint64
	dropped   atomic.Uint64

	rateWindow int64
	rateCount  int
	rateMu     sync.Mutex

	lastCollectErr string
}

type logTargetRuntime struct {
	idx    int
	target config.LogTarget

	lastErr string
	tick    uint64
	status  string

	cmd *CommandRunner

	// Windows-only: populated via log_targets_collector_windows.go
	evtx any
}

// NewLogTargetsCollector returns nil when no effective targets exist.
func NewLogTargetsCollector(cfg config.Config) *LogTargetsCollector {
	tg := EffectiveLogTargets(cfg)
	if len(tg) == 0 {
		return nil
	}
	host, _ := os.Hostname()
	ep := strings.TrimSpace(cfg.Service.EndpointID)
	if ep == "" {
		ep = "unknown"
	}
	lt := &LogTargetsCollector{
		cfg:        cfg,
		targets:    tg,
		endpointID: ep,
		hostname:   host,
		offsets:    make(map[string]persistedLogOffset),
	}
	lt.loadOffsets()
	for i := range lt.targets {
		st := logTargetRuntime{idx: i, target: lt.targets[i], status: "init"}
		ty := strings.ToLower(strings.TrimSpace(lt.targets[i].Type))
		switch ty {
		case "command", "full_command":
			st.cmd = NewCommandRunner(ty, lt.targets[i].Path)
			if lt.targets[i].Interval > 0 {
				st.cmd.SetPolicy(lt.targets[i].Interval, 0)
			}
		}
		lt.initTargetPlatform(&st)
		lt.states = append(lt.states, st)
	}
	return lt
}

func (l *LogTargetsCollector) offsetsPath() string {
	dd := strings.TrimSpace(l.cfg.Agent.DataDir)
	if dd == "" {
		return ""
	}
	return filepath.Join(dd, "log_targets_offsets.json")
}

func (l *LogTargetsCollector) loadOffsets() {
	p := l.offsetsPath()
	if p == "" {
		return
	}
	data, err := os.ReadFile(p)
	if err != nil {
		return
	}
	if m := loadPersistedLogOffsets(data); m != nil {
		for k, v := range m {
			l.offsets[k] = v
		}
	}
}

func (l *LogTargetsCollector) persistOffsets() {
	p := l.offsetsPath()
	if p == "" {
		return
	}
	l.mu.Lock()
	b, err := json.Marshal(l.offsets)
	l.mu.Unlock()
	if err != nil {
		return
	}
	_ = os.WriteFile(p, b, 0o600)
}

func (l *LogTargetsCollector) offsetKey(idx int, path string) string {
	return fmt.Sprintf("%d:%s", idx, path)
}

func (l *LogTargetsCollector) Name() string { return "log_targets" }

func (l *LogTargetsCollector) Collect(ctx context.Context) ([]Telemetry, error) {
	var out []Telemetry
	var errs []string
	fileEv := isLogTailFileEventsMode(l.cfg)

	for i := range l.states {
		if ctx.Err() != nil {
			break
		}
		st := &l.states[i]
		st.tick++
		ty := strings.ToLower(strings.TrimSpace(st.target.Type))

		switch ty {
		case "file":
			path := strings.TrimSpace(st.target.Path)
			key := l.offsetKey(st.idx, path)
			if fileEv {
				evs, n, err := l.drainPathFileEvents(ctx, st.idx, path, key)
				if err != nil {
					st.status = "error"
					st.lastErr = err.Error()
					errs = append(errs, fmt.Sprintf("%s: %v", path, err))
				} else {
					st.status = "ok"
					st.lastErr = ""
					l.readBytes.Add(n)
					out = append(out, evs...)
				}
			} else {
				n, err := l.drainTailChunk(ctx, path)
				if err != nil {
					st.status = "error"
					st.lastErr = err.Error()
					errs = append(errs, fmt.Sprintf("%s: %v", path, err))
				} else {
					st.status = "ok"
					st.lastErr = ""
					l.readBytes.Add(n)
				}
			}
		case "journald":
			if runtime.GOOS != "linux" {
				st.status = "error"
				st.lastErr = "journald requires linux"
				errs = append(errs, fmt.Sprintf("journald[%d]: linux only", st.idx))
				continue
			}
			evs, n, err := l.collectJournaldSnapshot(ctx, st)
			if err != nil {
				st.status = "error"
				st.lastErr = err.Error()
				errs = append(errs, fmt.Sprintf("journald[%d]: %v", st.idx, err))
			} else {
				st.status = "ok"
				st.lastErr = ""
				l.readBytes.Add(n)
				out = append(out, evs...)
			}
		case "command", "full_command":
			b, err := st.cmd.Run(ctx)
			if err != nil {
				st.status = "error"
				st.lastErr = err.Error()
				errs = append(errs, fmt.Sprintf("command[%d]: %v", st.idx, err))
			} else if len(b) > 0 {
				st.status = "ok"
				st.lastErr = ""
				l.readBytes.Add(uint64(len(b)))
			}
		case "eventchannel":
			if runtime.GOOS != "windows" {
				st.status = "error"
				st.lastErr = "eventchannel requires windows"
				errs = append(errs, fmt.Sprintf("evtx[%d]: windows only", st.idx))
				continue
			}
			ev, err := l.collectWindowsEventChannel(ctx, st)
			if err != nil {
				st.status = "error"
				st.lastErr = err.Error()
				errs = append(errs, fmt.Sprintf("evtx[%d]: %v", st.idx, err))
			} else {
				st.status = "ok"
				st.lastErr = ""
				out = append(out, ev...)
			}
		default:
			st.status = "error"
			st.lastErr = "unknown_type"
		}
	}
	if fileEv {
		l.persistOffsets()
	}
	l.mu.Lock()
	if len(errs) > 0 {
		l.lastCollectErr = strings.Join(errs, "; ")
	} else {
		l.lastCollectErr = ""
	}
	l.mu.Unlock()
	return out, nil
}

func (l *LogTargetsCollector) drainTailChunk(ctx context.Context, path string) (uint64, error) {
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

func (l *LogTargetsCollector) drainPathFileEvents(ctx context.Context, idx int, path, key string) ([]Telemetry, uint64, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return nil, 0, err
	}
	if fi.IsDir() {
		return nil, 0, fmt.Errorf("is directory")
	}
	dev, ino := fileTailIdentity(fi)
	l.mu.Lock()
	pos := l.offsets[key]
	l.mu.Unlock()
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
					Operation:    "log_target_line",
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
	l.mu.Lock()
	l.offsets[key] = persistedLogOffset{Dev: dev, Ino: ino, Off: newOff}
	l.mu.Unlock()
	return out, uint64(bytesRead), nil
}

func (l *LogTargetsCollector) allowFileEventEmit() bool {
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

// ExportMonitoringHealthRows implements ExportMonitoringHealthMulti.
func (l *LogTargetsCollector) ExportMonitoringHealthRows() []map[string]any {
	if l == nil {
		return nil
	}
	l.mu.Lock()
	globalErr := l.lastCollectErr
	l.mu.Unlock()

	var rows []map[string]any
	for i := range l.states {
		st := &l.states[i]
		ty := strings.ToLower(strings.TrimSpace(st.target.Type))
		name := fmt.Sprintf("log_target.%d", st.idx)
		stStr := st.status
		if stStr == "" {
			stStr = "unknown"
		}
		status := "healthy"
		if stStr == "error" || (globalErr != "" && strings.Contains(globalErr, fmt.Sprintf("[%d]", st.idx))) {
			status = "degraded"
		}
		if ty == "eventchannel" && runtime.GOOS != "windows" {
			status = "degraded"
			st.lastErr = "eventchannel requires windows"
		}
		if ty == "journald" && runtime.GOOS != "linux" {
			status = "degraded"
			if st.lastErr == "" {
				st.lastErr = "journald requires linux"
			}
		}
		src := MonitoringSource{
			Name:      name,
			OS:        runtime.GOOS,
			Source:    ty,
			Status:    status,
			EPSOut:    st.tick,
			LastError: st.lastErr,
			Dropped:   l.dropped.Load(),
			Notes:     logTargetFormatNotes(st.target.Format),
		}.ToMap()
		src["path"] = st.target.Path
		if q := strings.TrimSpace(st.target.Query); q != "" {
			src["query"] = q
		}
		rows = append(rows, src)
	}
	return rows
}

func logTargetFormatNotes(format string) string {
	f := strings.ToLower(strings.TrimSpace(format))
	switch f {
	case "", "raw", "syslog", "json":
		return ""
	default:
		return "format=" + format + " (hint only; parsers use raw line today)"
	}
}
