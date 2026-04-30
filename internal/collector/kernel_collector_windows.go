//go:build windows

package collector

import (
	"context"
	"os"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
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

	fimPrefixes []string // lowercased FIM path prefixes for file enrichment gate
	selfPID     uint32

	mu     sync.Mutex
	events []Telemetry
	cancel context.CancelFunc

	fileDropped uint64 // events filtered out because path is not under FIM set
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
	prefixes := make([]string, 0, len(cfg.Monitoring.FIMPaths))
	for _, p := range cfg.Monitoring.FIMPaths {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		prefixes = append(prefixes, strings.ToLower(p))
	}
	return &KernelCollector{
		driver:      d,
		buf:         kernel.NewRingBuffer(65536),
		endpointID:  endpointID,
		hostname:    host,
		cfg:         cfg,
		users:       users,
		fimPrefixes: prefixes,
		selfPID:     uint32(os.Getpid()),
	}
}

// ExportMonitoringHealth implements ExportMonitoringHealth for monitoring doctor snapshots.
func (kc *KernelCollector) ExportMonitoringHealth() map[string]any {
	if kc == nil || kc.driver == nil || kc.buf == nil {
		return nil
	}
	extras := map[string]any{
		"file_dropped":   atomic.LoadUint64(&kc.fileDropped),
		"fim_prefix_set": len(kc.fimPrefixes),
	}
	return KernelHealthMap("etw_kernel", kc.driver.Stats(), kc.buf.Stats(), extras)
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
		if tel == nil {
			continue
		}
		if !kc.acceptFileTelemetry(tel) {
			atomic.AddUint64(&kc.fileDropped, 1)
			continue
		}
		kc.maybeEnrichProcessImageHash(tel)
		kc.mu.Lock()
		kc.events = append(kc.events, *tel)
		kc.mu.Unlock()
	}
}

// acceptFileTelemetry drops Kernel-File events whose path is not under any
// configured FIM prefix and whose actor is the agent itself. Non-file events
// always pass through. When no FIM prefixes are configured the gate accepts
// everything (agent-policy decision: do not silently lose events).
func (kc *KernelCollector) acceptFileTelemetry(tel *Telemetry) bool {
	if tel.File == nil {
		return true
	}
	if uint32(tel.File.ActorPID) == kc.selfPID && kc.selfPID != 0 {
		return false
	}
	if len(kc.fimPrefixes) == 0 {
		return true
	}
	path := strings.ToLower(strings.TrimSpace(tel.File.Path))
	if path == "" {
		return false
	}
	for _, p := range kc.fimPrefixes {
		if strings.HasPrefix(path, p) {
			return true
		}
	}
	return false
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
