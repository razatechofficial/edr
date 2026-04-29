//go:build darwin

package collector

import (
	"context"
	"fmt"
	"os"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"github.com/razatechofficial/edr/internal/schema"
	"golang.org/x/sys/unix"
)

// DarwinProcSource is the macOS userland equivalent of the Linux ProcSource.
// It uses sysctl(KERN_PROC, KERN_PROC_ALL) via unix.SysctlKinfoProcSlice to
// enumerate processes without forking `ps`. Only newly visible pids emit
// telemetry; disappeared pids are reaped from the cache and from the shared
// LineageTracker, keeping memory bounded.
type DarwinProcSource struct {
	endpointID string
	hostname   string
	tracker    *LineageTracker

	mu    sync.Mutex // guards: known
	known map[int32]int64 // pid -> start_unix_ns

	scans   atomic.Uint64
	emitted atomic.Uint64
	skipped atomic.Uint64
	errs    atomic.Pointer[string]
}

// NewDarwinProcSource constructs a sysctl-based process source.
func NewDarwinProcSource(endpointID, hostname string, tracker *LineageTracker) *DarwinProcSource {
	if hostname == "" {
		if h, err := os.Hostname(); err == nil {
			hostname = h
		} else {
			hostname = "unknown"
		}
	}
	if tracker == nil {
		tracker = NewLineageTracker(0, 0)
	}
	return &DarwinProcSource{
		endpointID: endpointID,
		hostname:   hostname,
		tracker:    tracker,
		known:      make(map[int32]int64),
	}
}

// Snapshot returns ProcessEvent telemetry for newly seen pids.
func (s *DarwinProcSource) Snapshot(ctx context.Context) ([]Telemetry, error) {
	s.scans.Add(1)
	procs, err := unix.SysctlKinfoProcSlice("kern.proc.all")
	if err != nil {
		s.recordError(err)
		return nil, fmt.Errorf("sysctl kern.proc.all: %w", err)
	}
	now := time.Now().UTC()
	current := make(map[int32]int64, len(procs))
	out := make([]Telemetry, 0, 16)
	for _, kp := range procs {
		if ctx.Err() != nil {
			return out, ctx.Err()
		}
		pid := kp.Proc.P_pid
		if pid <= 0 {
			continue
		}
		startNS := int64(kp.Proc.P_starttime.Sec)*int64(time.Second) + int64(kp.Proc.P_starttime.Usec)*int64(time.Microsecond)
		current[pid] = startNS
		s.mu.Lock()
		prev, seen := s.known[pid]
		if seen && prev == startNS {
			s.mu.Unlock()
			s.skipped.Add(1)
			continue
		}
		s.known[pid] = startNS
		s.mu.Unlock()

		comm := cstringTrim(kp.Proc.P_comm[:])
		ppid := kp.Eproc.Ppid
		uid := kp.Eproc.Ucred.Uid
		s.tracker.Upsert(LineageEntry{
			PID:       uint32(pid),
			ParentPID: uint32(ppid),
			StartNS:   uint64(startNS),
			UID:       uid,
			Comm:      comm,
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
		}
		out = append(out, Telemetry{Process: &ev})
		s.emitted.Add(1)
	}

	s.mu.Lock()
	for pid := range s.known {
		if _, alive := current[pid]; !alive {
			delete(s.known, pid)
			s.tracker.Forget(uint32(pid))
		}
	}
	s.mu.Unlock()
	return out, nil
}

// ExportMonitoringHealth implements the per-source health interface.
func (s *DarwinProcSource) ExportMonitoringHealth() map[string]any {
	src := MonitoringSource{
		Name:    "process",
		OS:      "darwin",
		Source:  "sysctl",
		Status:  "healthy",
		EPSIn:   s.scans.Load(),
		EPSOut:  s.emitted.Load(),
		Dropped: s.skipped.Load(),
	}
	if errPtr := s.errs.Load(); errPtr != nil && *errPtr != "" {
		src.LastError = *errPtr
		src.Status = "degraded"
	}
	return src.ToMap()
}

func (s *DarwinProcSource) recordError(err error) {
	if err == nil {
		return
	}
	msg := err.Error()
	s.errs.Store(&msg)
}

func cstringTrim(b []byte) string {
	for i, c := range b {
		if c == 0 {
			return string(b[:i])
		}
	}
	return string(b)
}
