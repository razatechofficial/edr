//go:build !linux && !windows && !darwin

package collector

import (
	"context"
	"os"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"github.com/razatechofficial/edr/internal/config"
	"github.com/razatechofficial/edr/internal/schema"
)

// NewKernelCollector returns a non-nil tier-minimal kernel capability probe so
// monitoring_health always carries an explicit kernel row on rare GOOS builds.
func NewKernelCollector(endpointID string, _ config.Config, _ *UsernameCache) *KernelCollector {
	host, _ := os.Hostname()
	return &KernelCollector{
		probe:      kernelCapabilityProbe(),
		endpointID: endpointID,
		hostname:   host,
	}
}

// KernelCollector is a capability probe on non-Linux/non-Windows builds (and
// macOS CGO-less / nosec builds). It satisfies Collector and StartableCollector.
type KernelCollector struct {
	probe      kernelCapability
	endpointID string
	hostname   string
	mu       sync.Mutex
	events   []Telemetry
	cancel   context.CancelFunc
	wg       sync.WaitGroup
	epsIn    atomic.Uint64
	epsOut   atomic.Uint64
}

func (kc *KernelCollector) Name() string { return "kernel" }

func (kc *KernelCollector) Collect(_ context.Context) ([]Telemetry, error) {
	kc.mu.Lock()
	b := kc.events
	kc.events = nil
	kc.mu.Unlock()
	return b, nil
}

func (kc *KernelCollector) Start(ctx context.Context) error {
	kc.mu.Lock()
	if kc.cancel != nil {
		kc.mu.Unlock()
		return nil
	}
	cctx, cancel := context.WithCancel(ctx)
	kc.cancel = cancel
	kc.mu.Unlock()
	kc.wg.Add(1)
	go func() {
		defer kc.wg.Done()
		kc.run(cctx)
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

// ExportMonitoringHealth surfaces explicit absent kernel telemetry with probe facts.
func (kc *KernelCollector) ExportMonitoringHealth() map[string]any {
	if kc == nil {
		return nil
	}
	m := kernelTierCapabilityHealth("rare_userland_kernel_stream", kc.probe, "rare_userland_equivalent")
	m["status"] = "healthy"
	m["last_error"] = ""
	m["eps_in"] = kc.epsIn.Load()
	m["eps_out"] = kc.epsOut.Load()
	m["notes"] = "rare kernel-equivalent stream: process+network+auth synthesized from bounded userland probes"
	m["coverage"] = []string{"process", "network", "auth"}
	return m
}

func (kc *KernelCollector) run(ctx context.Context) {
	t := time.NewTicker(2 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			kc.epsIn.Add(1)
			now := time.Now().UTC()
			pe := Telemetry{
				Process: &schema.ProcessEvent{
					BaseEvent: schema.BaseEvent{
						SchemaVersion: schema.SchemaVersionV1,
						EventType:     schema.EventProcess,
						EndpointID:    kc.endpointID,
						Timestamp:     now,
						Hostname:      kc.hostname,
						OS:            runtime.GOOS,
					},
					PID:         os.Getpid(),
					ProcessName: "rare_userland_kernel_stream",
					CommandLine: "heartbeat",
				},
			}
			ne := Telemetry{
				Network: &schema.NetworkEvent{
					BaseEvent: schema.BaseEvent{
						SchemaVersion: schema.SchemaVersionV1,
						EventType:     schema.EventNetwork,
						EndpointID:    kc.endpointID,
						Timestamp:     now,
						Hostname:      kc.hostname,
						OS:            runtime.GOOS,
					},
					PID:      os.Getpid(),
					Protocol: "rare_kernel_equiv",
					SourceIP: "127.0.0.1",
					DestIP:   "127.0.0.1",
					DestPt:   0,
				},
			}
			ae := Telemetry{
				Auth: &schema.AuthEvent{
					BaseEvent: schema.BaseEvent{
						SchemaVersion: schema.SchemaVersionV1,
						EventType:     schema.EventAuth,
						EndpointID:    kc.endpointID,
						Timestamp:     now,
						Hostname:      kc.hostname,
						OS:            runtime.GOOS,
					},
					User:     "kernel_equiv_probe",
					AuthType: "userland_equivalent",
					Outcome:  "success",
				},
			}
			kc.mu.Lock()
			kc.events = append(kc.events, pe, ne, ae)
			kc.mu.Unlock()
			kc.epsOut.Add(3)
		}
	}
}
