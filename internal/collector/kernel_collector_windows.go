//go:build windows

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
	"golang.org/x/sys/windows"
)

// KernelCollector streams ETW kernel provider events into Telemetry.
type KernelCollector struct {
	driver     *kernel.ETWDriver
	buf        *kernel.RingBuffer
	endpointID string
	hostname   string
	cfg        config.Config
	users      *UsernameCache

	mu     sync.Mutex
	events []Telemetry
	cancel context.CancelFunc
}

func isWindowsElevated() bool {
	var tok windows.Token
	err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_QUERY, &tok)
	if err != nil {
		return false
	}
	defer tok.Close()
	return tok.IsElevated()
}

// NewKernelCollector returns an ETW-backed collector when running elevated.
func NewKernelCollector(endpointID string, cfg config.Config, users *UsernameCache) *KernelCollector {
	if !isWindowsElevated() {
		return nil
	}
	d, err := kernel.NewETWDriver(endpointID)
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
	return map[string]any{
		"driver":  kc.driver.Stats(),
		"ringbuf": kc.buf.Stats(),
	}
}

func (kc *KernelCollector) Name() string { return "kernel" }

func (kc *KernelCollector) Start(ctx context.Context) error {
	ctx, kc.cancel = context.WithCancel(ctx)
	pol := kernel.DefaultPolicy()
	m := kc.cfg.Monitoring
	pol.ETWWMIActivity = m.ETWWMIActivity
	pol.ETWPowerShellScript = m.ETWPowerShellScript
	pol.ETWNamedPipeHandles = m.ETWNamedPipeHandles
	pol.ETWBitsClient = m.ETWBitsClient
	pol.ETWTaskScheduler = m.ETWTaskScheduler
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

const maxWinExecImageHashBytes = 32 << 20

func (kc *KernelCollector) maybeEnrichProcessImageHash(tel *Telemetry) {
	if !kc.cfg.Monitoring.EnrichExecImageSHA256 || tel == nil || tel.Process == nil {
		return
	}
	p := tel.Process.ProcessPath
	if p == "" {
		return
	}
	if h := telemetryenrich.FileSHA256Hex(p, maxWinExecImageHashBytes); h != "" {
		tel.Process.ImageSHA256 = h
	}
}
