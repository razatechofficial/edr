//go:build linux

package collector

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/razatechofficial/edr/internal/schema"
	"golang.org/x/sys/unix"
)

// FanotifySource watches whole mount points for file modify/close-write/open
// activity. fanotify is the kernel-side equivalent of inotify but, when
// configured with FAN_MARK_MOUNT, it covers an entire filesystem with one
// kernel structure - dramatically cheaper than recursively adding inotify
// watches to thousands of directories.
//
// We only enable it when explicitly opted-in (it requires CAP_SYS_ADMIN on
// most distros). When inactive, fsnotify-based FileCollector remains the
// path-set monitor.
type FanotifySource struct {
	endpointID string
	hostname   string
	tracker    *LineageTracker
	mounts     []string

	mu       sync.Mutex // guards: fd, started
	fd       int
	started  bool

	emitted atomic.Uint64
	errs    atomic.Pointer[string]

	fileDedupe *LinuxFileDeduper

	livenessMu   sync.Mutex
	livenessRan  bool
	livenessOK   bool
	livenessNote string
}

// NewFanotifySource constructs a source that will watch the given mount
// points (or "/" when empty).
func NewFanotifySource(endpointID, hostname string, tracker *LineageTracker, mounts []string, dedupe *LinuxFileDeduper) *FanotifySource {
	if hostname == "" {
		if h, err := os.Hostname(); err == nil {
			hostname = h
		} else {
			hostname = "unknown"
		}
	}
	if len(mounts) == 0 {
		mounts = []string{"/"}
	}
	return &FanotifySource{
		endpointID: endpointID,
		hostname:   hostname,
		tracker:    tracker,
		mounts:     mounts,
		fd:         -1,
		fileDedupe: dedupe,
	}
}

// Start initializes fanotify and registers each mount. It is safe to call
// without root: the kernel will return EPERM and the source records the
// error in monitoring health without crashing the agent.
func (f *FanotifySource) Start() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.started {
		return nil
	}
	fd, err := unix.FanotifyInit(
		uint(unix.FAN_CLASS_NOTIF|unix.FAN_CLOEXEC|unix.FAN_NONBLOCK),
		uint(unix.O_RDONLY),
	)
	if err != nil {
		f.recordError(err)
		return fmt.Errorf("fanotify_init: %w", err)
	}
	mask := uint64(unix.FAN_MODIFY | unix.FAN_CLOSE_WRITE | unix.FAN_OPEN_EXEC)
	for _, m := range f.mounts {
		if err := unix.FanotifyMark(fd, unix.FAN_MARK_ADD|unix.FAN_MARK_MOUNT, mask, unix.AT_FDCWD, m); err != nil {
			_ = unix.Close(fd)
			f.recordError(err)
			return fmt.Errorf("fanotify_mark %s: %w", m, err)
		}
	}
	f.fd = fd
	f.started = true
	return nil
}

// Stop closes the fanotify descriptor.
func (f *FanotifySource) Stop() {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.fd >= 0 {
		_ = unix.Close(f.fd)
		f.fd = -1
	}
	f.started = false
}

// Run blocks until ctx is cancelled, draining the fanotify fd and pushing
// telemetry into out. The function honors ctx and never sends on a closed
// channel.
func (f *FanotifySource) Run(ctx context.Context, sink *StreamingSink) error {
	if err := f.Start(); err != nil {
		return err
	}
	defer f.Stop()

	f.runPostStartLivenessProbe(ctx)

	const evSize = 24 // sizeof(fanotify_event_metadata) on Linux for the variant we use
	buf := make([]byte, 4096)

	for {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		n, err := unix.Read(f.fd, buf)
		if err != nil {
			if errors.Is(err, unix.EAGAIN) || errors.Is(err, unix.EWOULDBLOCK) {
				select {
				case <-ctx.Done():
					return nil
				case <-time.After(50 * time.Millisecond):
					continue
				}
			}
			if errors.Is(err, unix.EINTR) {
				continue
			}
			f.recordError(err)
			return err
		}
		if n < evSize {
			continue
		}
		f.parseAndDispatch(ctx, buf[:n], sink)
	}
}

// parseAndDispatch walks a packed fanotify event buffer and emits FileEvent
// telemetry, resolving each fd to its absolute path via /proc/self/fd.
func (f *FanotifySource) parseAndDispatch(ctx context.Context, data []byte, sink *StreamingSink) {
	for len(data) >= 24 {
		// fanotify_event_metadata layout: u32 event_len, u8 vers, u8 reserved,
		// u16 metadata_len, u64 mask, s32 fd, s32 pid.
		eventLen := binary.LittleEndian.Uint32(data[0:4])
		if eventLen < 24 || int(eventLen) > len(data) {
			return
		}
		mask := binary.LittleEndian.Uint64(data[8:16])
		fd := int32(binary.LittleEndian.Uint32(data[16:20]))
		pid := int32(binary.LittleEndian.Uint32(data[20:24]))
		path := ""
		if fd >= 0 {
			if p, err := os.Readlink("/proc/self/fd/" + strconv.Itoa(int(fd))); err == nil {
				path = p
			}
			_ = unix.Close(int(fd))
		}
		op := fanotifyOpName(mask)
		fe := &schema.FileEvent{
			BaseEvent: schema.BaseEvent{
				SchemaVersion: schema.SchemaVersionV1,
				EventType:     schema.EventFile,
				EndpointID:    f.endpointID,
				Timestamp:     time.Now().UTC(),
				Hostname:      f.hostname,
				OS:            runtime.GOOS,
			},
			ActorPID:  int(pid),
			Path:      path,
			Operation: op,
		}
		if fe.Path != "" && f.fileDedupe != nil && !f.fileDedupe.AllowWithSource(fe.Path, DedupeSourceFanotify) {
			data = data[eventLen:]
			continue
		}
		if sink.Send(ctx, Telemetry{File: fe}) {
			f.emitted.Add(1)
		}
		data = data[eventLen:]
	}
}

func fanotifyOpName(mask uint64) string {
	switch {
	case mask&unix.FAN_MODIFY != 0:
		return "modify"
	case mask&unix.FAN_CLOSE_WRITE != 0:
		return "close_write"
	case mask&unix.FAN_OPEN_EXEC != 0:
		return "exec_open"
	default:
		return "fanotify"
	}
}

// ExportMonitoringHealth implements the per-source health interface.
func (f *FanotifySource) ExportMonitoringHealth() map[string]any {
	src := MonitoringSource{
		Name:   "fanotify_file",
		OS:     "linux",
		Source: "fanotify",
		Status: "healthy",
		EPSOut: f.emitted.Load(),
	}
	if !f.started {
		src.Status = "unavailable"
	}
	if errPtr := f.errs.Load(); errPtr != nil && *errPtr != "" {
		src.LastError = *errPtr
		src.Status = "degraded"
	}
	if f.fileDedupe != nil {
		src.Notes = fmt.Sprintf("file_dedupe_skipped=%d", f.fileDedupe.Skipped())
	}
	m := src.ToMap()
	f.livenessMu.Lock()
	ran, ok, note := f.livenessRan, f.livenessOK, f.livenessNote
	f.livenessMu.Unlock()
	if ran {
		m["liveness_probe_ok"] = ok
		if note != "" {
			m["liveness_probe_detail"] = note
		}
		if !ok && src.Status == "healthy" {
			m["status"] = "degraded"
		}
	}
	return m
}

// runPostStartLivenessProbe performs a one-shot write under a watched mount and expects a fanotify event.
func (f *FanotifySource) runPostStartLivenessProbe(ctx context.Context) {
	f.livenessMu.Lock()
	defer f.livenessMu.Unlock()
	f.livenessRan = true
	if !f.started || f.fd < 0 {
		f.livenessOK = false
		f.livenessNote = "not_started"
		return
	}
	dir := "/var/lib/edr"
	if err := os.MkdirAll(dir, 0o755); err != nil {
		f.livenessOK = false
		f.livenessNote = "mkdir:" + err.Error()
		return
	}
	path := filepath.Join(dir, ".fanotify_liveness_probe")
	if err := os.WriteFile(path, []byte("liveness\n"), 0o644); err != nil {
		f.livenessOK = false
		f.livenessNote = "write:" + err.Error()
		return
	}
	ctx2, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	buf := make([]byte, 4096)
	for {
		if ctx2.Err() != nil {
			f.livenessOK = false
			f.livenessNote = "timeout_or_cancelled"
			return
		}
		n, err := unix.Read(f.fd, buf)
		if err != nil {
			if errors.Is(err, unix.EAGAIN) || errors.Is(err, unix.EWOULDBLOCK) {
				select {
				case <-ctx2.Done():
					f.livenessOK = false
					f.livenessNote = "timeout_or_cancelled"
					return
				case <-time.After(15 * time.Millisecond):
				}
				continue
			}
			f.livenessOK = false
			f.livenessNote = err.Error()
			return
		}
		if n >= 24 {
			f.livenessOK = true
			f.livenessNote = ""
			return
		}
	}
}

func (f *FanotifySource) recordError(err error) {
	if err == nil {
		return
	}
	msg := err.Error()
	f.errs.Store(&msg)
}
