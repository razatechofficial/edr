package collector

import (
	"context"
	"runtime"

	"github.com/razatechofficial/edr/internal/config"
)

// NetworkStubCollector is a placeholder for future kernel/socket-level network telemetry.
type NetworkStubCollector struct{ endpointID string }

func NewNetworkStubCollector(endpointID string) *NetworkStubCollector {
	return &NetworkStubCollector{endpointID: endpointID}
}

func (n *NetworkStubCollector) Name() string { return "network" }

func (n *NetworkStubCollector) Collect(context.Context) ([]Telemetry, error) {
	return nil, nil
}

// AuthStubCollector is a placeholder for future auth / session telemetry.
type AuthStubCollector struct{ endpointID string }

func NewAuthStubCollector(endpointID string) *AuthStubCollector {
	return &AuthStubCollector{endpointID: endpointID}
}

func (a *AuthStubCollector) Name() string { return "auth" }

func (a *AuthStubCollector) Collect(context.Context) ([]Telemetry, error) {
	return nil, nil
}

// FileStubCollector is a placeholder for future file / FIM telemetry.
type FileStubCollector struct{ endpointID string }

func NewFileStubCollector(endpointID string) *FileStubCollector {
	return &FileStubCollector{endpointID: endpointID}
}

func (f *FileStubCollector) Name() string { return "file" }

func (f *FileStubCollector) Collect(context.Context) ([]Telemetry, error) {
	return nil, nil
}

// StartableCollector extends Collector with a lifecycle Start method needed
// by collectors that run background goroutines (e.g. KernelCollector).
type StartableCollector interface {
	Collector
	Start(ctx context.Context) error
	Stop()
}

// DefaultCollectors returns process, network, auth, and file collectors.
// Real implementations are used where available; stubs serve as fallbacks.
// Kernel-tier collectors (eBPF / ESF / ETW) attach when monitoring.mode allows,
// kernel_enabled is true, and the OS driver can start (e.g. Linux root).
// users resolves UIDs to names for kernel JSON/binary paths; if nil, a new cache is created.
func DefaultCollectors(cfg config.Config, users *UsernameCache) ([]Collector, error) {
	if users == nil {
		users = NewUsernameCache()
	}
	endpointID := cfg.Service.EndpointID
	pc, err := NewProcessCollector(endpointID)
	if err != nil {
		return nil, err
	}
	tracker := pc.LineageTracker()

	netCol := chooseNetworkCollector(cfg, endpointID, tracker)

	var authCol Collector = NewAuthStubCollector(endpointID)
	if ac := NewAuthCollector(endpointID, cfg.Agent.DataDir); ac != nil && (runtime.GOOS == "windows" || ac.logPath != "") {
		authCol = ac
	}

	var fileCol Collector
	fimPaths := cfg.Monitoring.FIMPaths
	if len(fimPaths) == 0 {
		fimPaths = nil
	}
	fc, fcErr := NewFileCollector(endpointID, fimPaths)
	if fcErr == nil {
		fileCol = fc
	} else {
		fileCol = NewFileStubCollector(endpointID)
	}

	cols := []Collector{pc, netCol, authCol, fileCol}

	if wantKernelTier(cfg) {
		if kc := NewKernelCollector(endpointID, cfg, users); kc != nil {
			cols = append(cols, kc)
		}
	}

	if dc := NewDNSCollector(endpointID); dc != nil {
		cols = append(cols, dc)
	}

	cols = extendWindowsEvtCollectors(cols, cfg, endpointID)

	if rc := NewRegistryCollector(endpointID); rc != nil {
		cols = append(cols, rc)
	}

	cols = extendLinuxMonitoringCollectors(cols, cfg, endpointID, tracker)
	cols = extendDarwinMonitoringCollectors(cols, cfg, endpointID, tracker)

	return cols, nil
}

func wantKernelTier(cfg config.Config) bool {
	m := cfg.Monitoring
	if m.Mode == "userland" {
		return false
	}
	return m.KernelEnabled
}
