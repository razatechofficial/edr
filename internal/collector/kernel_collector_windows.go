//go:build windows

package collector

import (
	"context"
	"os"
	"runtime"
	"sync"
	"time"

	"github.com/razatechofficial/edr/internal/kernel"
	"golang.org/x/sys/windows"
)

// KernelCollector streams ETW kernel provider events into Telemetry.
type KernelCollector struct {
	driver     *kernel.ETWDriver
	buf        *kernel.RingBuffer
	endpointID string
	hostname   string

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
func NewKernelCollector(endpointID string) *KernelCollector {
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
	}
}

func (kc *KernelCollector) Name() string { return "kernel" }

func (kc *KernelCollector) Start(ctx context.Context) error {
	ctx, kc.cancel = context.WithCancel(ctx)
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
		tel := MapKernelJSONToTelemetry(data, kc.endpointID, kc.hostname, runtime.GOOS)
		if tel != nil {
			kc.mu.Lock()
			kc.events = append(kc.events, *tel)
			kc.mu.Unlock()
		}
	}
}
