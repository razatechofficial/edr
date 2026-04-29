//go:build linux

package collector

import (
	"context"
	"fmt"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/razatechofficial/edr/internal/schema"
)

// ProcSource walks /proc once per Snapshot call and emits ProcessEvent
// telemetry only for processes that are newly visible since the previous
// snapshot. It is the lightweight, fork-free replacement for the legacy `ps
// -axo` polling loop and is designed to feed the userland fallback path when
// eBPF is unavailable. Per-pid start times disambiguate pid recycling.
type ProcSource struct {
	endpointID string
	hostname   string
	tracker    *LineageTracker

	mu        sync.Mutex // guards: known
	known     map[uint32]uint64 // pid -> start_ns

	scans     atomic.Uint64
	emitted   atomic.Uint64
	skipped   atomic.Uint64
	lastError atomic.Pointer[string]
}

// NewProcSource builds a /proc-based process source. tracker is the shared
// LineageTracker; if nil, a new one is created.
func NewProcSource(endpointID, hostname string, tracker *LineageTracker) *ProcSource {
	if tracker == nil {
		tracker = NewLineageTracker(0, 0)
	}
	if hostname == "" {
		if h, err := os.Hostname(); err == nil {
			hostname = h
		} else {
			hostname = "unknown"
		}
	}
	return &ProcSource{
		endpointID: endpointID,
		hostname:   hostname,
		tracker:    tracker,
		known:      make(map[uint32]uint64),
	}
}

// Snapshot scans /proc and returns ProcessEvent telemetry for newly seen
// pids. Disappeared pids are forgotten from both the source's own cache and
// the LineageTracker so memory does not grow unbounded.
func (s *ProcSource) Snapshot(ctx context.Context) ([]Telemetry, error) {
	s.scans.Add(1)
	entries, err := os.ReadDir("/proc")
	if err != nil {
		s.recordError(err)
		return nil, fmt.Errorf("readdir /proc: %w", err)
	}

	now := time.Now().UTC()
	currentRun := make(map[uint32]uint64, 256)
	out := make([]Telemetry, 0, 32)

	for _, e := range entries {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		if !e.IsDir() {
			continue
		}
		pid64, perr := strconv.ParseUint(e.Name(), 10, 32)
		if perr != nil {
			continue
		}
		pid := uint32(pid64)
		startNS, ppid, comm, ok := readProcStat(pid)
		if !ok {
			continue
		}
		currentRun[pid] = startNS

		s.mu.Lock()
		prevStart, seen := s.known[pid]
		if seen && prevStart == startNS {
			s.mu.Unlock()
			s.skipped.Add(1)
			continue
		}
		s.known[pid] = startNS
		s.mu.Unlock()

		exePath := readProcExe(pid)
		cmdline := readProcCmdline(pid)
		uid, gid := readProcStatusIDs(pid)

		s.tracker.Upsert(LineageEntry{
			PID:         pid,
			ParentPID:   ppid,
			StartNS:     startNS,
			UID:         uid,
			GID:         gid,
			ImagePath:   exePath,
			Comm:        comm,
			CommandLine: cmdline,
		})

		ev := schema.ProcessEvent{
			BaseEvent: schema.BaseEvent{
				SchemaVersion: schema.SchemaVersionV1,
				EventType:     schema.EventProcess,
				EndpointID:    s.endpointID,
				Timestamp:     now,
				Hostname:      s.hostname,
				OS:            runtime.GOOS,
			},
			PID:         int(pid),
			PPID:        int(ppid),
			ProcessName: comm,
			ProcessPath: exePath,
			CommandLine: cmdline,
		}
		out = append(out, Telemetry{Process: &ev})
		s.emitted.Add(1)
	}

	// Reap processes that disappeared since the last scan.
	s.mu.Lock()
	for pid := range s.known {
		if _, alive := currentRun[pid]; !alive {
			delete(s.known, pid)
			s.tracker.Forget(pid)
		}
	}
	s.mu.Unlock()

	return out, nil
}

// ExportMonitoringHealth implements ExportMonitoringHealth so the doctor can
// observe scan rate, emit count, and last error.
func (s *ProcSource) ExportMonitoringHealth() map[string]any {
	src := MonitoringSource{
		Name:    "process",
		OS:      "linux",
		Source:  "proc",
		Status:  "healthy",
		EPSOut:  s.emitted.Load(),
		EPSIn:   s.scans.Load(),
		Dropped: s.skipped.Load(),
	}
	if errPtr := s.lastError.Load(); errPtr != nil && *errPtr != "" {
		src.LastError = *errPtr
		src.Status = "degraded"
	}
	return src.ToMap()
}

func (s *ProcSource) recordError(err error) {
	if err == nil {
		return
	}
	msg := err.Error()
	s.lastError.Store(&msg)
}

// readProcStat parses /proc/<pid>/stat and returns (start_ns, ppid, comm, ok).
// Format reference: man 5 proc; field 14 is ppid, 22 is starttime in clock ticks.
func readProcStat(pid uint32) (uint64, uint32, string, bool) {
	data, err := os.ReadFile("/proc/" + strconv.FormatUint(uint64(pid), 10) + "/stat")
	if err != nil {
		return 0, 0, "", false
	}
	// comm is wrapped in parens and may contain spaces, so locate the trailing ')'.
	end := strings.LastIndexByte(string(data), ')')
	if end < 0 || end+2 >= len(data) {
		return 0, 0, "", false
	}
	commStart := strings.IndexByte(string(data), '(')
	if commStart < 0 || commStart >= end {
		return 0, 0, "", false
	}
	comm := string(data[commStart+1 : end])
	rest := strings.Fields(string(data[end+2:]))
	// rest[0] is state, rest[1] is ppid (field 4 overall), rest[19] is starttime (field 22 overall).
	if len(rest) < 20 {
		return 0, 0, "", false
	}
	ppid64, err := strconv.ParseUint(rest[1], 10, 32)
	if err != nil {
		return 0, 0, "", false
	}
	startTicks, err := strconv.ParseUint(rest[19], 10, 64)
	if err != nil {
		return 0, 0, "", false
	}
	// Convert ticks to ns; clock tick = 100Hz on most kernels (10ms each).
	// Using a fixed factor avoids a sysconf call on the hot path.
	const clockTickNS uint64 = 10_000_000
	return startTicks * clockTickNS, uint32(ppid64), comm, true
}

func readProcExe(pid uint32) string {
	target, err := os.Readlink("/proc/" + strconv.FormatUint(uint64(pid), 10) + "/exe")
	if err != nil {
		return ""
	}
	return target
}

func readProcCmdline(pid uint32) string {
	data, err := os.ReadFile("/proc/" + strconv.FormatUint(uint64(pid), 10) + "/cmdline")
	if err != nil {
		return ""
	}
	// cmdline arguments are NUL-separated.
	for i, b := range data {
		if b == 0 {
			data[i] = ' '
		}
	}
	return strings.TrimSpace(string(data))
}

func readProcStatusIDs(pid uint32) (uid, gid uint32) {
	data, err := os.ReadFile("/proc/" + strconv.FormatUint(uint64(pid), 10) + "/status")
	if err != nil {
		return 0, 0
	}
	for _, line := range strings.Split(string(data), "\n") {
		switch {
		case strings.HasPrefix(line, "Uid:"):
			fs := strings.Fields(line[4:])
			if len(fs) > 0 {
				if v, err := strconv.ParseUint(fs[0], 10, 32); err == nil {
					uid = uint32(v)
				}
			}
		case strings.HasPrefix(line, "Gid:"):
			fs := strings.Fields(line[4:])
			if len(fs) > 0 {
				if v, err := strconv.ParseUint(fs[0], 10, 32); err == nil {
					gid = uint32(v)
				}
			}
		}
	}
	return uid, gid
}
