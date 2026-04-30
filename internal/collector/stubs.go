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
	cfgEff := ApplyRegulatedDefaults(cfg)
	endpointID := cfgEff.Service.EndpointID
	pc, err := NewProcessCollector(endpointID)
	if err != nil {
		return nil, err
	}
	tracker := pc.LineageTracker()

	netCol := chooseNetworkCollector(cfgEff, endpointID, tracker)

	var authCol Collector
	var linuxJournalStandalone bool
	switch runtime.GOOS {
	case "windows":
		if ac := NewAuthCollector(endpointID, cfgEff.Agent.DataDir); ac != nil {
			authCol = ac
		} else {
			authCol = NewAuthStubCollector(endpointID)
		}
	case "linux":
		authCol, linuxJournalStandalone = pickLinuxAuth(cfgEff, endpointID, tracker)
	case "darwin":
		authCol = pickDarwinAuth(cfgEff, endpointID, tracker)
	default:
		if ac := NewAuthCollector(endpointID, cfgEff.Agent.DataDir); ac != nil && ac.logPath != "" {
			authCol = ac
		} else {
			authCol = NewAuthStubCollector(endpointID)
		}
	}

	var fileCol Collector
	fimPaths := cfgEff.Monitoring.FIMPaths
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

	if WantKernelTier(cfgEff) {
		if kc := NewKernelCollector(endpointID, cfgEff, users); kc != nil {
			cols = append(cols, kc)
		}
	}

	if dc := NewDNSCollector(endpointID, cfgEff); dc != nil {
		cols = append(cols, dc)
	}

	cols = extendWindowsEvtCollectors(cols, cfgEff, endpointID)

	if rc := NewRegistryCollector(endpointID); rc != nil {
		cols = append(cols, rc)
	}

	if runtime.GOOS == "windows" {
		WireWindowsKernelRegistryETW(cols)
	}

	cols = extendLinuxMonitoringCollectors(cols, cfgEff, endpointID, tracker, linuxJournalStandalone)
	cols = extendDarwinMonitoringCollectors(cols, cfgEff, endpointID, tracker)

	if InventoryWanted(cfgEff) {
		cols = append(cols, NewInventoryCollector(cfgEff))
	}

	if ltc := NewLogTailCollector(cfgEff); ltc != nil {
		cols = append(cols, ltc)
	}
	if pc := NewPostureCollector(cfgEff); pc != nil {
		cols = append(cols, pc)
	}

	if err := ValidateRegulatedMonitoring(cfgEff, cols); err != nil {
		return nil, err
	}
	return cols, nil
}

// WantKernelTier reports whether kernel-tier collectors should attach per config.
func WantKernelTier(cfg config.Config) bool {
	m := cfg.Monitoring
	if m.Mode == "userland" {
		return false
	}
	return m.KernelEnabled
}
