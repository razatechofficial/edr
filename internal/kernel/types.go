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

	// There is no FIMPaths field. One existed and no platform consumed
	// it: the Linux driver pushed it into an eBPF path_filter map that no
	// program read and that could not have worked (see file_monitor.c),
	// Windows reads cfg.Monitoring.FIMPaths directly, and nothing ever
	// assigned it on any platform. A policy field that claims to scope
	// file monitoring and does not is worse than its absence, because it
	// is the field an operator would reach for.
	//
	// Userspace FIM path scoping lives in internal/collector (see
	// ResolveFIMPaths) and is real.

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
	LostEvents          uint32 `json:"lost_events,omitempty"`
	RealtimeBuffersLost uint32 `json:"realtime_buffers_lost,omitempty"`

	// KernelReserveFailures counts events the kernel threw away because
	// the BPF ring buffer they were destined for was full. Linux eBPF
	// only; zero elsewhere.
	//
	// It is separate from EventsDropped because the two are losses at
	// different points and only one of them userspace can otherwise see.
	// EventsDropped counts records that reached the driver and failed to
	// decode. A record lost to a full ring buffer never reached the
	// driver, never reached the userspace RingBuffer, and never credited
	// the capability report -- so before this field every surface the
	// agent exposes read exactly as it reads on an idle host.
	KernelReserveFailures uint64 `json:"kernel_reserve_failures,omitempty"`

	// KernelSubmitted counts events the kernel reserved and filled, which
	// is the denominator KernelReserveFailures needs to be read against.
	KernelSubmitted uint64 `json:"kernel_submitted,omitempty"`

	// KernelFilterDrops counts events an in-kernel pid filter dropped
	// before a reserve was attempted. A non-zero value is normal: the
	// agent always filters its own pid.
	KernelFilterDrops uint64 `json:"kernel_filter_drops,omitempty"`

	// KernelLossByRing attributes KernelReserveFailures to the ring buffer
	// that was full, which is the thing to resize or drain faster.
	KernelLossByRing map[string]uint64 `json:"kernel_loss_by_ring,omitempty"`
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
