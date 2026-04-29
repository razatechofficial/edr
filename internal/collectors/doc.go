// Package collectors is the legacy ring-buffer-driven collector pipeline.
//
// It is no longer wired into the runtime agent (see internal/agent/agent.go,
// which uses internal/collector instead) and is retained only because
// pkg/events/types_test.go imports its typed event structs.
//
// Deprecated: do not use Manager, NewManager, decodeRawEvent, EventSubType, or
// any non-event-struct API from this package in new code. The shared
// monitoring primitives live in internal/collector (LineageTracker,
// EventDeduper, BoundedLRU, BoundedRing, EPSLimiter, Group). The USB watcher
// in hardware.go will be relocated to internal/collector/usb_collector_linux.go
// during the Linux monitoring phase.
package collectors
