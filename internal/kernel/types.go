package kernel

import (
	"context"
	"time"

	"github.com/razatechofficial/edr/pkg/events"
)

// EventCallback is invoked for each kernel event received from the driver.
type EventCallback func(event interface{})

// EventPolicy configures which events the kernel driver should capture.
type EventPolicy struct {
	ProcessEvents  bool
	FileEvents     bool
	NetworkEvents  bool
	RegistryEvents bool
	MemoryEvents   bool
	DNSEvents      bool
	AuthEvents     bool
	ModuleEvents   bool
	MountEvents    bool
	PtraceEvents   bool
	SignalEvents   bool
	// SchedEvents enables Linux eBPF scheduler tracepoint telemetry (high volume).
	SchedEvents bool
	// LSMFimEvents enables Linux BPF LSM observe-only FIM events (path_unlink/path_rename/inode_setattr).
	LSMFimEvents bool

	// MutePaths lists process paths that should be silently ignored.
	MutePaths []string

	// MutePIDs lists PIDs whose events should be dropped.
	MutePIDs []uint32

	// FIMPaths lists path prefixes the kernel-side file-monitor should
	// emit events for. On Linux this is pushed into the eBPF path_filter
	// map so the verifier-bounded prefix match runs in-kernel, dropping
	// the vast majority of unrelated file events before they reach the
	// ringbuf. Empty list disables filtering (capture everything).
	FIMPaths []string

	// Windows-only optional ETW providers (high volume; default off).
	ETWWMIActivity      bool
	ETWPowerShellScript bool
	ETWNamedPipeHandles bool
	ETWBitsClient       bool
	ETWTaskScheduler    bool
	// ETWThreatIntel enables probing Microsoft-Windows-Threat-Intelligence ETW (gated by product config).
	ETWThreatIntel bool
	// ETWSecurityProviders enables AMSI, Code Integrity, AppLocker, and Windows Defender ETW (optional sessions).
	ETWSecurityProviders bool
	// ESFAuthDenyBudgetMs (macOS): when >0, deny ESF AUTH if remaining deadline ms is below this threshold.
	ESFAuthDenyBudgetMs int
	// KernelFileObjectCache correlates Kernel-File events to paths via FileObject handle (WHIDS-class).
	KernelFileObjectCache bool

	// TrustedTeamIDs (macOS, P1-9): Apple-developer team identifiers
	// whose signed binaries are auto-allowed on ESF AUTH events with a
	// short-lived cache. Default: empty (no team-id allowlist; every
	// AUTH still flows through the handler). Use to whitelist e.g.
	// Apple's "D6PSC4G3J7" and the EDR's own team id so trusted
	// software does not pay the AUTH roundtrip cost. Unknown or
	// adhoc-signed binaries always go through the full path.
	TrustedTeamIDs []string
}

// DefaultPolicy returns an EventPolicy with all event types enabled.
func DefaultPolicy() EventPolicy {
	return EventPolicy{
		ProcessEvents:  true,
		FileEvents:     true,
		NetworkEvents:  true,
		RegistryEvents: true,
		MemoryEvents:   true,
		DNSEvents:      true,
		AuthEvents:     true,
		ModuleEvents:   true,
		MountEvents:    true,
		PtraceEvents:   true,
		SignalEvents:   true,
		SchedEvents:    false,
		LSMFimEvents:   false,
		// Windows: broad security ETW (AMSI / CI / AppLocker / Defender); ignored on other OSes.
		ETWSecurityProviders: true,
	}
}

// Sentinel errors for monitoring orchestration live in errors.go (ErrKernelUnavailable, etc.).
//
// Driver is the interface all platform-specific kernel drivers implement.
type Driver interface {
	// Start begins kernel event collection. Events are written to the ring buffer.
	Start(ctx context.Context, buf *RingBuffer) error

	// Stop cleanly detaches from all kernel hooks and releases resources.
	Stop() error

	// SetPolicy updates the event collection policy without restarting.
	SetPolicy(policy EventPolicy) error

	// Name returns the driver implementation name (e.g., "ebpf", "esf", "etw").
	Name() string

	// Capabilities reports which event types this driver supports.
	Capabilities() []events.EventType
}

// AuthDecision represents a kernel authorization decision (macOS ESF, Linux LSM).
type AuthDecision uint8

const (
	// AuthAllow permits the operation to proceed.
	AuthAllow AuthDecision = iota
	// AuthDeny blocks the operation.
	AuthDeny
)

// AuthHandler is called for authorization events that can block operations.
type AuthHandler func(event interface{}) AuthDecision

// DriverStats contains runtime statistics for a kernel driver.
type DriverStats struct {
	EventsReceived  uint64
	EventsDropped   uint64
	EventsProcessed uint64
	LastEventTime   time.Time
	UptimeSeconds   float64
	ErrorCount      uint64

	// CollectionMode is OS/driver-specific (e.g. Windows ETW secure vs standard realtime).
	CollectionMode string `json:"collection_mode,omitempty"`

	// LostEvents / RealtimeBuffersLost are populated on Windows ETW (ControlTrace QUERY); zero elsewhere.
	LostEvents              uint32 `json:"lost_events,omitempty"`
	RealtimeBuffersLost     uint32 `json:"realtime_buffers_lost,omitempty"`
}

// ETWProviderHealth records per-provider subscribe status (Windows ETW).
type ETWProviderHealth struct {
	Name   string `json:"name"`
	Active bool   `json:"active"`
	Error  string `json:"last_error,omitempty"`
}

// ThreatIntelHealth summarizes ETW Threat-Intel probe outcome (Windows).
type ThreatIntelHealth struct {
	Probed bool   `json:"probed"`
	OK     bool   `json:"ok"`
	Status string `json:"status"`
	Reason string `json:"reason,omitempty"`
}
