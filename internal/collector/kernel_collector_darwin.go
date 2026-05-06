//go:build darwin && cgo && !nosec

package collector

import (
	"context"
	"os"
	"runtime"
	"strings"
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

	neCtl    *kernel.NetworkExtensionCtl
	revProbe *kernel.ESFRevocationProbe
	wg       sync.WaitGroup
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
		neCtl:      kernel.NewNetworkExtensionCtl(strings.TrimSpace(cfg.Monitoring.DarwinNEBundleID)),
		revProbe:   kernel.NewESFRevocationProbe(),
	}
}

// ExportMonitoringHealth implements ExportMonitoringHealth for monitoring doctor snapshots.
func (kc *KernelCollector) ExportMonitoringHealth() map[string]any {
	if kc == nil || kc.driver == nil || kc.buf == nil {
		return nil
	}
	extras := map[string]any{
		"esf_auth":       kc.driver.AuthHealth(),
		"ne_ctl":         kc.neCtl.Health(),
		"esf_revocation": kc.revProbe.Health(),
	}
	if im := kc.driver.ESFNotifyIngestMetrics(); im != nil {
		for k, v := range im {
			extras[k] = v
		}
	}
	rs := kc.buf.Stats()
	extras["ring_bytes_used"] = rs.BytesUsed
	extras["ring_capacity_bytes"] = rs.Capacity
	extras["ring_backlog_pct"] = rs.BacklogPct
	extras["esf_operator_mute_prefixes"] = len(kc.cfg.Monitoring.ESFMutePathPrefixes)
	if ah := kc.driver.AuthHealth(); ah != nil {
		if v, ok := ah["auth_denials"].(uint64); ok && v > 0 {
			extras["tamper_esf_auth_denials"] = v
		}
	}
	posture := map[string]any{
		"esf_operator_mute_prefixes": len(kc.cfg.Monitoring.ESFMutePathPrefixes),
	}
	tamperSignals := map[string]any{}
	if ne, ok := extras["ne_ctl"].(map[string]any); ok {
		if st, _ := ne["network_extension_status"].(string); st == "degraded" {
			tamperSignals["ne_degraded"] = true
		}
	}
	if rv, ok := extras["esf_revocation"].(map[string]any); ok {
		if st, _ := rv["esf_revocation_status"].(string); st == "degraded" {
			tamperSignals["esf_revocation_degraded"] = true
		}
	}
	extras = MergeTamperHealth(extras, "darwin_esf_ne_monitoring", posture, tamperSignals)
	return KernelHealthMap("esf", kc.driver.Stats(), kc.buf.Stats(), extras)
}

func (kc *KernelCollector) Name() string { return "kernel" }

func (kc *KernelCollector) Start(ctx context.Context) error {
	ctx, kc.cancel = context.WithCancel(ctx)
	pol := kernel.DefaultPolicy()
	pol.MutePaths = append(kernel.DefaultESFMutePathPrefixes(), kc.cfg.Monitoring.ESFMutePathPrefixes...)
	_ = kc.driver.SetPolicy(pol)
	_ = kc.neCtl.Start()
	kc.revProbe.SetSysextBundleID(kc.cfg.Monitoring.DarwinNEBundleID)
	if err := kc.driver.Start(ctx, kc.buf); err != nil {
		kc.neCtl.Stop()
		return err
	}
	kc.wg.Add(3)
	go func() {
		defer kc.wg.Done()
		kc.revProbe.Run(ctx)
	}()
	go func() {
		defer kc.wg.Done()
		kc.readLoop(ctx)
	}()
	go func() {
		defer kc.wg.Done()
		kc.controlPlaneLoop(ctx)
	}()
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
	kc.neCtl.Stop()
	_ = kc.driver.Stop()
	kc.wg.Wait()
}

func (kc *KernelCollector) controlPlaneLoop(ctx context.Context) {
	t := time.NewTicker(45 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if ok := kc.neCtl.Probe(ctx); !ok {
				kc.revProbe.RecordFailure("network_extension_probe_failed")
			}
		}
	}
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
