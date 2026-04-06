package collectors

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/razatechofficial/edr/internal/kernel"
	"github.com/razatechofficial/edr/pkg/events"
	"go.uber.org/zap"
)

const usbSysPath = "/sys/bus/usb/devices"

// USBEvent is emitted when a USB device is inserted or removed.
type USBEvent struct {
	Timestamp  time.Time `json:"timestamp"`
	Action     string    `json:"action"`
	DevicePath string    `json:"device_path"`
	Vendor     string    `json:"vendor,omitempty"`
	Product    string    `json:"product,omitempty"`
	Serial     string    `json:"serial,omitempty"`
}

// HardwareCollector monitors hardware changes such as USB device
// insertion and removal by watching sysfs via fsnotify.
type HardwareCollector struct {
	logger  *zap.Logger
	out     chan<- interface{}
	watcher *fsnotify.Watcher
	cancel  context.CancelFunc
	wg      sync.WaitGroup
}

// NewHardwareCollector creates a HardwareCollector with the given logger.
func NewHardwareCollector(logger *zap.Logger) *HardwareCollector {
	return &HardwareCollector{logger: logger}
}

// Name returns the collector identifier.
func (c *HardwareCollector) Name() string { return "hardware" }

// EventTypes returns nil; hardware events come from filesystem watchers,
// not the kernel ring buffer.
func (c *HardwareCollector) EventTypes() []events.EventType { return nil }

// Start initializes the filesystem watcher on Linux. On other platforms
// the collector logs a notice and returns without error.
func (c *HardwareCollector) Start(ctx context.Context, _ *kernel.RingBuffer, out chan<- interface{}) error {
	c.out = out

	if runtime.GOOS != "linux" {
		c.logger.Info("USB hardware monitoring only supported on Linux")
		return nil
	}

	w, err := fsnotify.NewWatcher()
	if err != nil {
		return fmt.Errorf("creating fsnotify watcher: %w", err)
	}
	c.watcher = w

	if err := w.Add(usbSysPath); err != nil {
		_ = w.Close()
		c.watcher = nil
		c.logger.Warn("cannot watch USB sysfs path",
			zap.String("path", usbSysPath), zap.Error(err))
		return nil
	}

	ctx, c.cancel = context.WithCancel(ctx)
	c.wg.Add(1)
	go c.watchLoop(ctx)
	return nil
}

// Stop cancels the watch loop and closes the filesystem watcher.
func (c *HardwareCollector) Stop() error {
	if c.cancel != nil {
		c.cancel()
	}
	c.wg.Wait()
	if c.watcher != nil {
		return c.watcher.Close()
	}
	return nil
}

func (c *HardwareCollector) processRaw(_ *RawEvent) {}

func (c *HardwareCollector) watchLoop(ctx context.Context) {
	defer c.wg.Done()

	for {
		select {
		case <-ctx.Done():
			return
		case event, ok := <-c.watcher.Events:
			if !ok {
				return
			}
			c.handleFsEvent(event)
		case err, ok := <-c.watcher.Errors:
			if !ok {
				return
			}
			c.logger.Error("fsnotify error", zap.Error(err))
		}
	}
}

func (c *HardwareCollector) handleFsEvent(event fsnotify.Event) {
	var action string
	switch {
	case event.Op&fsnotify.Create != 0:
		action = "insert"
	case event.Op&fsnotify.Remove != 0:
		action = "remove"
	default:
		return
	}

	devPath := event.Name

	c.emit(&USBEvent{
		Timestamp:  time.Now().UTC(),
		Action:     action,
		DevicePath: devPath,
		Vendor:     readSysAttr(devPath, "idVendor"),
		Product:    readSysAttr(devPath, "idProduct"),
		Serial:     readSysAttr(devPath, "serial"),
	})
}

func (c *HardwareCollector) emit(evt interface{}) {
	select {
	case c.out <- evt:
	default:
		c.logger.Warn("output channel full, dropping hardware event")
	}
}

func readSysAttr(devPath, attr string) string {
	data, err := os.ReadFile(filepath.Join(devPath, attr))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}
