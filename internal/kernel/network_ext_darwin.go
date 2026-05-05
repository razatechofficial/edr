//go:build darwin

package kernel

import (
	"sync/atomic"
)

// NetworkExtensionCtl is a scaffold for integrating with Network Extension /
// System Extension lifecycle health. Full NE provider wiring lives outside
// this repository until product signing gates complete.
type NetworkExtensionCtl struct {
	active atomic.Bool
}

// NewNetworkExtensionCtl constructs a NE monitoring scaffold.
func NewNetworkExtensionCtl() *NetworkExtensionCtl {
	return &NetworkExtensionCtl{}
}

// Start marks the scaffold active (placeholder for future NE attach).
func (n *NetworkExtensionCtl) Start() error {
	if n == nil {
		return ErrNetworkExtensionUnavailable
	}
	n.active.Store(true)
	return nil
}

// Stop clears the scaffold active flag.
func (n *NetworkExtensionCtl) Stop() {
	if n == nil {
		return
	}
	n.active.Store(false)
}

// Health reports integration posture for monitoring_health.json.
func (n *NetworkExtensionCtl) Health() map[string]any {
	if n == nil {
		return map[string]any{"network_extension": "nil"}
	}
	status := "stopped"
	if n.active.Load() {
		status = "scaffold_active"
	}
	return map[string]any{
		"network_extension_status": status,
		"network_extension_note": "NE/System Extension provider integration pending; scaffold only",
	}
}
