//go:build linux

package collector

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/razatechofficial/edr/internal/schema"
)

// usbSysPath is the well-known sysfs root that exposes USB device files.
// fsnotify on this directory yields create/remove events when devices are
// inserted or unplugged.
const usbSysPath = "/sys/bus/usb/devices"

// USBCollector emits FileEvent telemetry tagged "usb_attach"/"usb_detach"
// when USB devices arrive or leave. It is the relocated, supported
// replacement for the unwired internal/collectors.HardwareCollector.
type USBCollector struct {
	endpointID string
	hostname   string

	mu      sync.Mutex // guards: watcher, started
	watcher *fsnotify.Watcher
	started bool

	emitted atomic.Uint64
	errs    atomic.Pointer[string]
}

// NewUSBCollector constructs a USB watcher.
func NewUSBCollector(endpointID, hostname string) *USBCollector {
	if hostname == "" {
		if h, err := os.Hostname(); err == nil {
			hostname = h
		} else {
			hostname = "unknown"
		}
	}
	return &USBCollector{endpointID: endpointID, hostname: hostname}
}

// Run begins watching usbSysPath and emits Telemetry until ctx is cancelled.
// On non-Linux it is a no-op (build tag protects compilation, but at runtime
// the sysfs path may simply be absent).
func (u *USBCollector) Run(ctx context.Context, sink *StreamingSink) error {
	if _, err := os.Stat(usbSysPath); err != nil {
		u.recordError(err)
		return err
	}
	w, err := fsnotify.NewWatcher()
	if err != nil {
		u.recordError(err)
		return err
	}
	if err := w.Add(usbSysPath); err != nil {
		_ = w.Close()
		u.recordError(err)
		return err
	}
	u.mu.Lock()
	u.watcher = w
	u.started = true
	u.mu.Unlock()

	defer func() {
		_ = w.Close()
		u.mu.Lock()
		u.started = false
		u.watcher = nil
		u.mu.Unlock()
	}()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case ev, ok := <-w.Events:
			if !ok {
				return errors.New("usb watcher closed")
			}
			tel := u.toTelemetry(ev)
			if tel == nil {
				continue
			}
			if sink.Send(ctx, *tel) {
				u.emitted.Add(1)
			}
		case err, ok := <-w.Errors:
			if !ok {
				return errors.New("usb watcher error channel closed")
			}
			u.recordError(err)
		}
	}
}

func (u *USBCollector) toTelemetry(ev fsnotify.Event) *Telemetry {
	if ev.Name == "" {
		return nil
	}
	op := ""
	switch {
	case ev.Op&fsnotify.Create != 0:
		op = "usb_attach"
	case ev.Op&fsnotify.Remove != 0:
		op = "usb_detach"
	default:
		return nil
	}
	return &Telemetry{
		File: &schema.FileEvent{
			BaseEvent: schema.BaseEvent{
				SchemaVersion: schema.SchemaVersionV1,
				EventType:     schema.EventFile,
				EndpointID:    u.endpointID,
				Timestamp:     time.Now().UTC(),
				Hostname:      u.hostname,
				OS:            runtime.GOOS,
			},
			Path:      filepath.Clean(ev.Name),
			Operation: op,
		},
	}
}

// ExportMonitoringHealth implements the per-source health interface.
func (u *USBCollector) ExportMonitoringHealth() map[string]any {
	src := MonitoringSource{
		Name:   "usb",
		OS:     "linux",
		Source: "fsnotify-sysfs",
		Status: "healthy",
		EPSOut: u.emitted.Load(),
	}
	if !u.started {
		src.Status = "unavailable"
	}
	if errPtr := u.errs.Load(); errPtr != nil && *errPtr != "" {
		src.LastError = *errPtr
		src.Status = "degraded"
	}
	return src.ToMap()
}

func (u *USBCollector) recordError(err error) {
	if err == nil {
		return
	}
	msg := err.Error()
	if strings.TrimSpace(msg) == "" {
		return
	}
	u.errs.Store(&msg)
}
