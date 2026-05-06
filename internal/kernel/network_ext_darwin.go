//go:build darwin

package kernel

import (
	"context"
	"os/exec"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// NetworkExtensionCtl observes Network Extension / System Extension lifecycle health.
type NetworkExtensionCtl struct {
	active atomic.Bool
	mu     sync.RWMutex

	bundleID              string
	state                 string
	stateMachine          string
	lastError             string
	lastProbeUnix         int64
	lastStatusChangeUnix  int64
	degradedCount         atomic.Uint64
	probeAttempts         atomic.Uint64

	probeCmd func(ctx context.Context) ([]byte, error)
}

// NewNetworkExtensionCtl constructs a NE monitoring handle; bundleID filters systemextensionsctl output when set.
func NewNetworkExtensionCtl(bundleID string) *NetworkExtensionCtl {
	return &NetworkExtensionCtl{
		bundleID:     strings.TrimSpace(bundleID),
		state:        "init",
		stateMachine: "init",
		probeCmd: func(ctx context.Context) ([]byte, error) {
			return exec.CommandContext(ctx, "/usr/sbin/systemextensionsctl", "list").CombinedOutput()
		},
	}
}

// Start marks the scaffold active.
func (n *NetworkExtensionCtl) Start() error {
	if n == nil {
		return ErrNetworkExtensionUnavailable
	}
	n.active.Store(true)
	n.mu.Lock()
	n.state = "running_scaffold"
	n.stateMachine = "awaiting_approval"
	n.lastError = ""
	now := time.Now().Unix()
	n.lastProbeUnix = now
	n.lastStatusChangeUnix = now
	n.mu.Unlock()
	return nil
}

// Stop clears the active flag.
func (n *NetworkExtensionCtl) Stop() {
	if n == nil {
		return
	}
	n.active.Store(false)
	n.mu.Lock()
	n.state = "stopped"
	n.stateMachine = "stopped"
	n.mu.Unlock()
}

// Probe executes systemextensionsctl list and updates state machine + bundle match.
func (n *NetworkExtensionCtl) Probe(ctx context.Context) bool {
	if n == nil || !n.active.Load() {
		return false
	}
	n.probeAttempts.Add(1)
	probeCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	cmd := n.probeCmd
	if cmd == nil {
		cmd = func(ctx context.Context) ([]byte, error) {
			return exec.CommandContext(ctx, "/usr/sbin/systemextensionsctl", "list").CombinedOutput()
		}
	}
	out, err := cmd(probeCtx)
	now := time.Now().Unix()

	n.mu.Lock()
	defer n.mu.Unlock()
	n.lastProbeUnix = now
	prevSm := n.stateMachine

	if err != nil {
		n.state = "degraded"
		n.stateMachine = "degraded"
		n.lastError = err.Error()
		n.degradedCount.Add(1)
		if prevSm != n.stateMachine {
			n.lastStatusChangeUnix = now
		}
		return false
	}
	text := strings.ToLower(string(out))
	if n.bundleID != "" {
		bid := strings.Contains(text, strings.ToLower(n.bundleID))
		active := strings.Contains(text, "activated") || strings.Contains(text, "active")
		if bid && active {
			n.state = "running"
			n.stateMachine = "running"
			n.lastError = ""
			if prevSm != n.stateMachine {
				n.lastStatusChangeUnix = now
			}
			return true
		}
		n.state = "degraded"
		n.stateMachine = "awaiting_approval"
		n.lastError = "bundle_id_not_found_in_sysext_list"
		n.degradedCount.Add(1)
		if prevSm != n.stateMachine {
			n.lastStatusChangeUnix = now
		}
		return false
	}
	if !strings.Contains(text, "active") {
		n.state = "degraded"
		n.stateMachine = "degraded"
		n.lastError = "systemextensionsctl output missing active entries"
		n.degradedCount.Add(1)
		if prevSm != n.stateMachine {
			n.lastStatusChangeUnix = now
		}
		return false
	}
	n.state = "running_scaffold"
	n.stateMachine = "running"
	n.lastError = ""
	if prevSm != n.stateMachine {
		n.lastStatusChangeUnix = now
	}
	return true
}

// Health reports integration posture for monitoring_health.json.
func (n *NetworkExtensionCtl) Health() map[string]any {
	if n == nil {
		return map[string]any{"network_extension": "nil"}
	}
	n.mu.RLock()
	defer n.mu.RUnlock()
	status := n.state
	if status == "" {
		status = "stopped"
	}
	return map[string]any{
		"network_extension_status":            status,
		"network_extension_state_machine":     n.stateMachine,
		"network_extension_bundle_id_filter":    n.bundleID,
		"network_extension_note":              "NE/System Extension health probe; configure darwin_ne_bundle_id for strict matching",
		"network_extension_last_probe":        n.lastProbeUnix,
		"network_extension_last_status_change": n.lastStatusChangeUnix,
		"network_extension_probe_attempts":     n.probeAttempts.Load(),
		"network_extension_degraded_cnt":       n.degradedCount.Load(),
		"network_extension_active":            n.active.Load(),
		"network_extension_last_error":        n.lastError,
	}
}
