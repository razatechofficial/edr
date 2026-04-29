//go:build windows

package collector

import (
	"context"
	"fmt"
	"os"
	"runtime"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	"github.com/razatechofficial/edr/internal/schema"
	"golang.org/x/sys/windows"
)

// WindowsProcSource is the Windows userland process source. It enumerates
// running processes via CreateToolhelp32Snapshot + Process32NextW exactly
// once per Snapshot call, emitting telemetry only for newly seen pids.
//
// The previous Windows fallback in collector.go merely emitted the agent's
// own process; this is the audit-mandated replacement that gives broad
// visibility even when ETW is unavailable (e.g. non-elevated).
type WindowsProcSource struct {
	endpointID string
	hostname   string
	tracker    *LineageTracker

	mu    sync.Mutex // guards: known
	known map[uint32]uint32 // pid -> ppid (cheap signature for "still alive")

	scans   atomic.Uint64
	emitted atomic.Uint64
	skipped atomic.Uint64
	errs    atomic.Pointer[string]
}

// NewWindowsProcSource constructs a Toolhelp32-based process source.
func NewWindowsProcSource(endpointID, hostname string, tracker *LineageTracker) *WindowsProcSource {
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
	return &WindowsProcSource{
		endpointID: endpointID,
		hostname:   hostname,
		tracker:    tracker,
		known:      make(map[uint32]uint32),
	}
}

// Snapshot enumerates the process table and returns ProcessEvent telemetry
// for newly visible pids. Disappeared pids are reaped from the cache and
// from the LineageTracker.
func (s *WindowsProcSource) Snapshot(ctx context.Context) ([]Telemetry, error) {
	s.scans.Add(1)
	snap, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		s.recordError(err)
		return nil, fmt.Errorf("CreateToolhelp32Snapshot: %w", err)
	}
	defer windows.CloseHandle(snap)

	var pe windows.ProcessEntry32
	pe.Size = uint32(unsafe.Sizeof(pe))
	if err := windows.Process32First(snap, &pe); err != nil {
		s.recordError(err)
		return nil, fmt.Errorf("Process32First: %w", err)
	}

	now := time.Now().UTC()
	current := make(map[uint32]uint32, 256)
	out := make([]Telemetry, 0, 16)

	for {
		if ctx.Err() != nil {
			return out, ctx.Err()
		}
		current[pe.ProcessID] = pe.ParentProcessID

		s.mu.Lock()
		prevPpid, seen := s.known[pe.ProcessID]
		if seen && prevPpid == pe.ParentProcessID {
			s.mu.Unlock()
			s.skipped.Add(1)
		} else {
			s.known[pe.ProcessID] = pe.ParentProcessID
			s.mu.Unlock()
			name := windows.UTF16ToString(pe.ExeFile[:])
			s.tracker.Upsert(LineageEntry{
				PID:       pe.ProcessID,
				ParentPID: pe.ParentProcessID,
				Comm:      name,
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
				PID:         int(pe.ProcessID),
				PPID:        int(pe.ParentProcessID),
				ProcessName: name,
			}
			out = append(out, Telemetry{Process: &ev})
			s.emitted.Add(1)
		}

		if err := windows.Process32Next(snap, &pe); err != nil {
			break
		}
	}

	s.mu.Lock()
	for pid := range s.known {
		if _, alive := current[pid]; !alive {
			delete(s.known, pid)
			s.tracker.Forget(pid)
		}
	}
	s.mu.Unlock()
	return out, nil
}

// ExportMonitoringHealth implements the per-source health interface.
func (s *WindowsProcSource) ExportMonitoringHealth() map[string]any {
	src := MonitoringSource{
		Name:    "process",
		OS:      "windows",
		Source:  "toolhelp32",
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

func (s *WindowsProcSource) recordError(err error) {
	if err == nil {
		return
	}
	msg := err.Error()
	s.errs.Store(&msg)
}
