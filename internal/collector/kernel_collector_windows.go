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

	mfCtl  *kernel.MinifilterCtl
	wfpCtl *kernel.WFPCtl

	// registryPeer optionally suppresses RegistryCollector polling while
	// Kernel-Registry ETW is active (see WireWindowsKernelRegistryETW).
	registryPeer *RegistryCollector

	mu     sync.Mutex
	events []Telemetry
	cancel context.CancelFunc
	wg     sync.WaitGroup

	fileDropped uint64 // events filtered out because path is not under FIM set

	controlPlaneDegraded atomic.Uint64

	prio         *kernelRingPriority
	priorityDrop atomic.Uint64

	jsonMapOpts KernelJSONOpts

	ppidChecks    atomic.Uint64
	ppidMismatch  atomic.Uint64
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
	kc := &KernelCollector{
		driver:      d,
		buf:         kernel.NewRingBuffer(65536),
		endpointID:  endpointID,
		hostname:    host,
		cfg:         cfg,
		users:       users,
		fimPrefixes: prefixes,
		selfPID:     uint32(os.Getpid()),
		mfCtl:       kernel.NewMinifilterCtl(strings.TrimSpace(cfg.Monitoring.WindowsMinifilterPort)),
		wfpCtl:      kernel.NewWFPCtl(),
		jsonMapOpts: KernelJSONOpts{
			TLSFingerprintLocal: cfg.Monitoring.TLSFingerprintLocal,
			CommunityIDLocal:    cfg.Monitoring.CommunityIDLocal,
		},
	}
	kc.prio = newKernelRingPriority(cfg)
	return kc
}

// ExportMonitoringHealth implements ExportMonitoringHealth for monitoring doctor snapshots.
func (kc *KernelCollector) ExportMonitoringHealth() map[string]any {
	if kc == nil || kc.driver == nil || kc.buf == nil {
		return nil
	}
	extras := map[string]any{
		"file_dropped":   atomic.LoadUint64(&kc.fileDropped),
		"fim_prefix_set": len(kc.fimPrefixes),
		"etw_providers":  kc.driver.ProviderHealthSnapshot(),
	}
	if pd := kc.priorityDrop.Load(); pd > 0 {
		extras["priority_sampling_kernel_drops"] = pd
	}
	extras["etw_threat_intel_requested"] = kc.cfg.Monitoring.ETWThreatIntel
	tih := kc.driver.ThreatIntelHealthSnapshot()
	extras["etw_threat_intel_probed"] = tih.Probed
	extras["etw_threat_intel_ok"] = tih.OK
	if tih.Status != "" {
		extras["etw_threat_intel_status"] = tih.Status
	}
	if tih.Reason != "" {
		extras["etw_threat_intel_reason"] = tih.Reason
	}
	rs := kc.buf.Stats()
	extras["ring_bytes_used"] = rs.BytesUsed
	extras["ring_capacity_bytes"] = rs.Capacity
	extras["ring_backlog_pct"] = rs.BacklogPct
	if im := kc.driver.IngestMetrics(); im != nil {
		for k, v := range im {
			extras[k] = v
		}
	}
	if kc.wfpCtl != nil {
		wh := kc.wfpCtl.Health()
		wh["wfp_mirror_diag_only"] = kc.cfg.Monitoring.WindowsWFPMirrorDiagOnly
		extras["wfp_ctl"] = wh
	}
	extras["wfp_mirror_diag_only"] = kc.cfg.Monitoring.WindowsWFPMirrorDiagOnly
	if kc.mfCtl != nil {
		extras["minifilter_ctl"] = kc.mfCtl.Health()
	}
	el, rl := kc.driver.SnapshotETWSessionLoss()
	extras["etw_lost_events"] = el
	extras["etw_buffers_lost_realtime"] = rl
	if sh := kernel.WindowsServiceHardeningPosture(); sh != nil {
		extras["service_hardening_posture"] = sh
	}
	controlReady := kc.controlPlaneReady(extras)
	extras["control_plane_required"] = kc.cfg.Monitoring.WindowsControlPlaneRequired
	extras["control_plane_ready"] = controlReady
	extras["control_plane_degraded_count"] = kc.controlPlaneDegraded.Load()
	posture := kernel.WindowsCollectionPosture()
	extras["windows_collection_posture"] = posture
	extras["ppid_spoof_checks"] = kc.ppidChecks.Load()
	extras["ppid_spoof_mismatches"] = kc.ppidMismatch.Load()
	tamperSignals := map[string]any{}
	for k, v := range kc.driver.TamperMetrics() {
		extras[k] = v
		tamperSignals[k] = v
	}
	if ti := kc.driver.ThreatIntelTamperSignals(); ti != nil {
		for k, v := range ti {
			tamperSignals[k] = v
		}
	}
	if wfp, ok := extras["wfp_ctl"].(map[string]any); ok {
		if s, _ := wfp["state"].(string); s == "degraded" {
			tamperSignals["wfp_ctl_degraded"] = true
		}
	}
	if mf, ok := extras["minifilter_ctl"].(map[string]any); ok {
		if s, _ := mf["state"].(string); s == "degraded" {
			tamperSignals["minifilter_ctl_degraded"] = true
		}
	}
	extras = MergeTamperHealth(extras, "windows_kernel_monitoring", posture, tamperSignals)
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
	pol.ETWThreatIntel = m.ETWThreatIntel
	pol.ETWSecurityProviders = m.ETWSecurityProviders
	pol.KernelFileObjectCache = m.ETWKernelFileObjectCache
	_ = kc.driver.SetPolicy(pol)
	if !kc.ensureWindowsControlPlane(false) && kc.cfg.Monitoring.WindowsControlPlaneRequired {
		return kernel.ErrKernelUnavailable
	}
	if err := kc.driver.Start(ctx, kc.buf); err != nil {
		return err
	}
	if kc.registryPeer != nil {
		kc.registryPeer.SetETWActive(true)
	}
	kc.wg.Add(2)
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
	if kc.registryPeer != nil {
		kc.registryPeer.SetETWActive(false)
	}
	if kc.wfpCtl != nil {
		kc.wfpCtl.Stop()
	}
	if kc.mfCtl != nil {
		kc.mfCtl.Stop()
	}
	_ = kc.driver.Stop()
	kc.wg.Wait()
}

func (kc *KernelCollector) controlPlaneLoop(ctx context.Context) {
	t := time.NewTicker(30 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			kc.ensureWindowsControlPlane(true)
		}
	}
}

func healthCauseIsPermanent(h map[string]any) bool {
	if h == nil {
		return false
	}
	cc, _ := h["cause_class"].(string)
	return cc == "permanent"
}

func wfpHealthReady(h map[string]any) bool {
	if h == nil {
		return false
	}
	v, _ := h["engine_open"].(bool)
	return v
}

func minifilterHealthReady(h map[string]any) bool {
	if h == nil {
		return false
	}
	v, _ := h["connected"].(bool)
	return v
}

func (kc *KernelCollector) ensureWindowsControlPlane(recover bool) bool {
	ok := true
	if kc.cfg.Monitoring.WindowsWFPCtlProbe && kc.wfpCtl != nil {
		h := kc.wfpCtl.Health()
		if recover && healthCauseIsPermanent(h) {
			if !wfpHealthReady(h) {
				ok = false
			}
		} else {
			var err error
			if recover {
				err = kc.wfpCtl.Recover()
			} else {
				err = kc.wfpCtl.Start()
			}
			if err != nil {
				ok = false
			}
		}
	}
	if strings.TrimSpace(kc.cfg.Monitoring.WindowsMinifilterPort) != "" && kc.mfCtl != nil {
		h := kc.mfCtl.Health()
		if recover && healthCauseIsPermanent(h) {
			if !minifilterHealthReady(h) {
				ok = false
			}
		} else {
			var err error
			if recover {
				err = kc.mfCtl.Recover()
			} else {
				err = kc.mfCtl.Start()
			}
			if err != nil {
				ok = false
			}
		}
	}
	if !ok {
		kc.controlPlaneDegraded.Add(1)
	}
	return ok
}

func (kc *KernelCollector) controlPlaneReady(extras map[string]any) bool {
	wfpReady := true
	if kc.cfg.Monitoring.WindowsWFPCtlProbe {
		wfpReady = false
		if h, ok := extras["wfp_ctl"].(map[string]any); ok {
			if v, ok := h["engine_open"].(bool); ok {
				wfpReady = v
			}
		}
	}
	mfReady := true
	if strings.TrimSpace(kc.cfg.Monitoring.WindowsMinifilterPort) != "" {
		mfReady = false
		if h, ok := extras["minifilter_ctl"].(map[string]any); ok {
			if v, ok := h["connected"].(bool); ok {
				mfReady = v
			}
		}
	}
	return wfpReady && mfReady
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
		tel := MapKernelJSONToTelemetry(data, kc.endpointID, kc.hostname, runtime.GOOS, kc.users, &kc.jsonMapOpts)
		if tel == nil {
			continue
		}
		kc.maybeDetectPPIDSpoof(tel)
		kc.prio.observeRing(kc.buf)
		if kc.prio != nil && !kc.prio.allowSample(tel) {
			kc.priorityDrop.Add(1)
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
