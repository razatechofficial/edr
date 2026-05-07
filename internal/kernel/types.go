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

	// MutePaths lists process paths that should be silently ignored.
	MutePaths []string

	// MutePIDs lists PIDs whose events should be dropped.
	MutePIDs []uint32

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
