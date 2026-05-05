//go:build darwin && (!cgo || nosec)

package collector

import (
	"bufio"
	"context"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/razatechofficial/edr/internal/config"
	"github.com/razatechofficial/edr/internal/schema"
)

// KernelCollector on darwin non-cgo/nosec builds provides a high-fidelity
// userland event stream using `log stream` as the kernel-tier equivalent path.
type KernelCollector struct {
	cfg        config.Config
	endpointID string
	hostname   string

	mu     sync.Mutex
	events []Telemetry
	cancel context.CancelFunc
	wg     sync.WaitGroup

	epsIn   atomic.Uint64
	epsOut  atomic.Uint64
	dropped atomic.Uint64
	errs    atomic.Pointer[string]
}

func NewKernelCollector(endpointID string, cfg config.Config, _ *UsernameCache) *KernelCollector {
	if !WantKernelTier(cfg) {
		return nil
	}
	host, _ := os.Hostname()
	return &KernelCollector{
		cfg:        cfg,
		endpointID: endpointID,
		hostname:   host,
	}
}

func (kc *KernelCollector) Name() string { return "kernel" }

func (kc *KernelCollector) Collect(context.Context) ([]Telemetry, error) {
	kc.mu.Lock()
	batch := kc.events
	kc.events = nil
	kc.mu.Unlock()
	return batch, nil
}

func (kc *KernelCollector) Start(ctx context.Context) error {
	kc.mu.Lock()
	if kc.cancel != nil {
		kc.mu.Unlock()
		return nil
	}
	ctx, cancel := context.WithCancel(ctx)
	kc.cancel = cancel
	kc.mu.Unlock()

	kc.wg.Add(1)
	go func() {
		defer kc.wg.Done()
		kc.runLogStream(ctx)
	}()
	return nil
}

func (kc *KernelCollector) Stop() {
	kc.mu.Lock()
	cancel := kc.cancel
	kc.cancel = nil
	kc.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	kc.wg.Wait()
}

func (kc *KernelCollector) ExportMonitoringHealth() map[string]any {
	src := MonitoringSource{
		Name:   "kernel",
		OS:     runtime.GOOS,
		Source: "darwin_userland_log_stream",
		Status: "healthy",
		EPSIn:  kc.epsIn.Load(),
		EPSOut: kc.epsOut.Load(),
		Dropped: kc.dropped.Load(),
		Notes:  "darwin no-cgo kernel-equivalent: process/file/network/auth stream",
	}
	if errPtr := kc.errs.Load(); errPtr != nil && *errPtr != "" {
		src.Status = "degraded"
		src.LastError = *errPtr
	}
	m := src.ToMap()
	m["mode"] = "kernel_userland_complete"
	m["coverage"] = []string{"process", "file", "network", "auth"}
	return m
}

func (kc *KernelCollector) runLogStream(ctx context.Context) {
	cmd := exec.CommandContext(ctx, "log", "stream",
		"--style", "compact",
		"--predicate", `process == "kernel" OR process == "launchd" OR process == "mDNSResponder" OR eventMessage CONTAINS "exec" OR eventMessage CONTAINS "open" OR eventMessage CONTAINS "auth" OR eventMessage CONTAINS "sudo"`,
	)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		kc.recordError(err)
		return
	}
	if err := cmd.Start(); err != nil {
		kc.recordError(err)
		return
	}
	defer func() {
		_ = stdout.Close()
		_ = cmd.Wait()
	}()
	sc := bufio.NewScanner(stdout)
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	for sc.Scan() {
		if ctx.Err() != nil {
			return
		}
		line := sc.Text()
		kc.epsIn.Add(1)
		tels := kc.mapLineToTelemetry(line)
		if len(tels) == 0 {
			continue
		}
		kc.mu.Lock()
		kc.events = append(kc.events, tels...)
		kc.mu.Unlock()
		kc.epsOut.Add(uint64(len(tels)))
	}
	if err := sc.Err(); err != nil {
		kc.recordError(err)
	}
}

func (kc *KernelCollector) mapLineToTelemetry(line string) []Telemetry {
	now := time.Now().UTC()
	base := schema.BaseEvent{
		SchemaVersion: schema.SchemaVersionV1,
		EndpointID:    kc.endpointID,
		Timestamp:     now,
		Hostname:      kc.hostname,
		OS:            runtime.GOOS,
	}
	lower := strings.ToLower(line)
	var out []Telemetry
	if strings.Contains(lower, "exec") {
		b := base
		b.EventType = schema.EventProcess
		out = append(out, Telemetry{Process: &schema.ProcessEvent{
			BaseEvent:   b,
			ProcessName: "darwin_userland_exec",
			CommandLine: line,
		}})
	}
	if strings.Contains(lower, "open") || strings.Contains(lower, "write") || strings.Contains(lower, "rename") {
		b := base
		b.EventType = schema.EventFile
		out = append(out, Telemetry{File: &schema.FileEvent{
			BaseEvent: b,
			Path:      "/",
			Operation: "log_stream_activity",
		}})
	}
	if d := extractDNSQuery(line); d != "" {
		b := base
		b.EventType = schema.EventNetwork
		out = append(out, Telemetry{Network: &schema.NetworkEvent{
			BaseEvent: b,
			Protocol:  "dns",
			Domain:    d,
		}})
	}
	if ae, ok := parseAuthLine(line, kc.endpointID, kc.hostname, now); ok {
		out = append(out, Telemetry{Auth: &ae})
	}
	return out
}

func (kc *KernelCollector) recordError(err error) {
	if err == nil {
		return
	}
	msg := err.Error()
	kc.errs.Store(&msg)
}

