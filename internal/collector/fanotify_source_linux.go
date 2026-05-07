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

var fanotifyInitFn = unix.FanotifyInit

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

	// lastMountFP is a sha256 hex of /proc/self/mountinfo; when it changes we re-mark mounts.
	lastMountFP string
	// fanReportFIDCap records whether kernel headers expose FAN_REPORT_FID.
	fanReportFIDCap bool
	// fanReportFIDEnabled tracks whether FAN_REPORT_FID was successfully enabled at init.
	fanReportFIDEnabled bool

	mountFID        *mountFIDCache
	fidResolveOK    atomic.Uint64
	fidResolveFail  atomic.Uint64
	fidResolveByName atomic.Uint64

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
		fanReportFIDCap: probeFanReportFIDCapability(),
		mountFID:        newMountFIDCache(64),
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
	flags := uint(unix.FAN_CLASS_NOTIF | unix.FAN_CLOEXEC | unix.FAN_NONBLOCK)
	usedFID := false
	if f.fanReportFIDCap {
		flags |= uint(unix.FAN_REPORT_FID | unix.FAN_REPORT_DIR_FID)
		usedFID = true
	}
	fd, err := fanotifyInitFn(flags, uint(unix.O_RDONLY))
	if err != nil && f.fanReportFIDCap {
		// Kernel doesn't support report-fid despite headers; retry without FID mode.
		fd, err = fanotifyInitFn(uint(unix.FAN_CLASS_NOTIF|unix.FAN_CLOEXEC|unix.FAN_NONBLOCK), uint(unix.O_RDONLY))
		if err == nil {
			usedFID = false
		}
	}
	if err != nil {
		f.recordError(err)
		return fmt.Errorf("fanotify_init: %w", err)
	}
	f.fanReportFIDEnabled = usedFID
	mask := uint64(unix.FAN_MODIFY | unix.FAN_CLOSE_WRITE | unix.FAN_OPEN_EXEC)
	for _, m := range f.mounts {
		if err := unix.FanotifyMark(fd, unix.FAN_MARK_ADD|unix.FAN_MARK_MOUNT, mask, unix.AT_FDCWD, m); err != nil {
			_ = unix.Close(fd)
			f.recordError(err)
			return fmt.Errorf("fanotify_mark %s: %w", m, err)
		}
	}
	if fp, err := readMountinfoFingerprint(); err == nil {
		f.lastMountFP = fp
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
	if f.mountFID != nil {
		f.mountFID.closeAll()
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

	watchCtx, watchCancel := context.WithCancel(ctx)
	defer watchCancel()
	go f.runMountTableWatch(watchCtx)

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
		} else if f.fanReportFIDEnabled && int(fd) == unix.FAN_NOFD {
			if p := f.resolveFanotifyFIDPath(data[:eventLen]); p != "" {
				path = p
				f.fidResolveOK.Add(1)
			} else {
				f.fidResolveFail.Add(1)
			}
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

func probeFanReportFIDCapability() bool {
	// Build/runtime probe: available in recent kernels and x/sys headers.
	return unix.FAN_REPORT_FID != 0
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
	if f.fanReportFIDCap {
		if src.Notes != "" {
			src.Notes += "; "
		}
		src.Notes += "fan_report_fid_cap=true"
		if f.fanReportFIDEnabled {
			src.Notes += "; fan_report_fid_enabled=true"
		} else {
			src.Notes += "; fan_report_fid_enabled=false"
		}
		if n := f.fidResolveOK.Load(); n > 0 {
			src.Notes += fmt.Sprintf("; fan_report_fid_resolved_ok=%d", n)
		}
		if n := f.fidResolveFail.Load(); n > 0 {
			src.Notes += fmt.Sprintf("; fan_report_fid_resolve_fail=%d", n)
		}
		if n := f.fidResolveByName.Load(); n > 0 {
			src.Notes += fmt.Sprintf("; fan_report_fid_resolve_namepath=%d", n)
		}
	} else {
		if src.Notes != "" {
			src.Notes += "; "
		}
		src.Notes += "fan_report_fid_cap=false"
	}
	m := src.ToMap()
	m["fan_report_fid_resolved"] = f.fidResolveOK.Load() > 0
	m["fan_fid_resolve_namepath"] = f.fidResolveByName.Load()
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
