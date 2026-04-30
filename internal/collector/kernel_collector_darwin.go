//go:build darwin && cgo && !nosec

package collector

import (
	"context"
	"os"
	"runtime"
	"sync"
	"time"

	"github.com/razatechofficial/edr/internal/config"
	"github.com/razatechofficial/edr/internal/kernel"
	"github.com/razatechofficial/edr/internal/telemetryenrich"
)

// KernelCollector streams Endpoint Security Framework events into Telemetry.
type KernelCollector struct {
	driver     *kernel.ESFDriver
	buf        *kernel.RingBuffer
	endpointID string
	hostname   string
	cfg        config.Config
	users      *UsernameCache

	mu     sync.Mutex
	events []Telemetry
	cancel context.CancelFunc
}

// NewKernelCollector starts the ESF driver when running as root.
func NewKernelCollector(endpointID string, cfg config.Config, users *UsernameCache) *KernelCollector {
	if os.Getuid() != 0 {
		return nil
	}
	d, err := kernel.NewESFDriver(endpointID)
	if err != nil {
		return nil
	}
	host, _ := os.Hostname()
	return &KernelCollector{
		driver:     d,
		buf:        kernel.NewRingBuffer(65536),
		endpointID: endpointID,
		hostname:   host,
		cfg:        cfg,
		users:      users,
	}
}

// ExportMonitoringHealth implements ExportMonitoringHealth for monitoring doctor snapshots.
func (kc *KernelCollector) ExportMonitoringHealth() map[string]any {
	if kc == nil || kc.driver == nil || kc.buf == nil {
		return nil
	}
	return KernelHealthMap("esf", kc.driver.Stats(), kc.buf.Stats(), nil)
}

func (kc *KernelCollector) Name() string { return "kernel" }

func (kc *KernelCollector) Start(ctx context.Context) error {
	ctx, kc.cancel = context.WithCancel(ctx)
	pol := kernel.DefaultPolicy()
	pol.MutePaths = append(kernel.DefaultESFMutePathPrefixes(), kc.cfg.Monitoring.ESFMutePathPrefixes...)
	_ = kc.driver.SetPolicy(pol)
	if err := kc.driver.Start(ctx, kc.buf); err != nil {
		return err
	}
	go kc.readLoop(ctx)
	return nil
}

func (kc *KernelCollector) Collect(_ context.Context) ([]Telemetry, error) {
	kc.mu.Lock()
	batch := kc.events
	kc.events = nil
	kc.mu.Unlock()
	return batch, nil
}

func (kc *KernelCollector) Stop() {
	if kc.cancel != nil {
		kc.cancel()
	}
	_ = kc.driver.Stop()
}

const maxDarwinExecImageHashBytes = 32 << 20

func (kc *KernelCollector) maybeEnrichProcessImageHash(tel *Telemetry) {
	if !kc.cfg.Monitoring.EnrichExecImageSHA256 || tel == nil || tel.Process == nil {
		return
	}
	p := tel.Process.ProcessPath
	if p == "" {
		return
	}
	if h := telemetryenrich.FileSHA256Hex(p, maxDarwinExecImageHashBytes); h != "" {
		tel.Process.ImageSHA256 = h
	}
}

func (kc *KernelCollector) readLoop(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}
		data, err := kc.buf.TryRead()
		if err != nil || data == nil {
			time.Sleep(time.Millisecond)
			continue
		}
		tel := MapKernelJSONToTelemetry(data, kc.endpointID, kc.hostname, runtime.GOOS, kc.users)
		if tel != nil {
			kc.maybeEnrichProcessImageHash(tel)
			kc.mu.Lock()
			kc.events = append(kc.events, *tel)
			kc.mu.Unlock()
		}
	}
}
