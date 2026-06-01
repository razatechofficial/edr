package comms

import (
	"context"
	"time"

	"go.uber.org/zap"

	"github.com/razatechofficial/edr/pkg/protocol"
)

// PolicyApplyFunc applies a changed control-plane policy on the agent.
type PolicyApplyFunc func(ctx context.Context, resp *protocol.PolicyResponse) error

// PolicyHashFunc returns the last applied control-plane policy hash.
type PolicyHashFunc func() string

// SetPolicyApply registers the handler invoked when GetPolicy reports a change.
func (cp *ControlPlane) SetPolicyApply(fn PolicyApplyFunc) {
	if cp == nil {
		return
	}
	cp.policyApply = fn
}

// SetPolicyHashReader registers a callback returning the current policy hash.
func (cp *ControlPlane) SetPolicyHashReader(fn PolicyHashFunc) {
	if cp == nil {
		return
	}
	cp.policyHashFn = fn
}

// SyncPolicy fetches and applies the latest control-plane policy when changed.
func (cp *ControlPlane) SyncPolicy(ctx context.Context) error {
	if cp == nil || cp.client == nil {
		return nil
	}
	current := ""
	if cp.policyHashFn != nil {
		current = cp.policyHashFn()
	}
	resp, err := cp.client.GetPolicy(ctx, current)
	if err != nil {
		return err
	}
	if resp == nil || !resp.GetChanged() {
		return nil
	}
	if cp.policyApply == nil {
		cp.logger.Info("control_plane policy changed but no apply handler registered",
			zap.String("policy_hash", resp.GetPolicyHash()),
			zap.Int("bundles", len(resp.GetRuleBundles())),
		)
		return nil
	}
	if err := cp.policyApply(ctx, resp); err != nil {
		return err
	}
	cp.logger.Info("control_plane policy applied",
		zap.String("policy_hash", resp.GetPolicyHash()),
		zap.Int("bundles", len(resp.GetRuleBundles())),
	)
	return nil
}

func (cp *ControlPlane) policyLoop(ctx context.Context) {
	interval := cp.policySyncSec
	if interval <= 0 {
		interval = 5 * time.Minute
	}

	select {
	case <-cp.stopCh:
		return
	case <-ctx.Done():
		return
	case <-time.After(2 * time.Second):
	}

	if err := cp.SyncPolicy(ctx); err != nil {
		cp.logger.Warn("control_plane initial policy sync failed", zap.Error(err))
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-cp.stopCh:
			return
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := cp.SyncPolicy(ctx); err != nil {
				cp.logger.Warn("control_plane policy sync failed", zap.Error(err))
			}
		}
	}
}
