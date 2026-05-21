package sca

import (
	"context"
	"log/slog"
)

// FilterApplicablePolicies returns policies whose requirements block matches the
// current host. Policies without requirements are
// included. Policies that fail requirements are skipped entirely.
func FilterApplicablePolicies(ctx context.Context, policies []Policy, cfg EvalConfig, logger *slog.Logger) []Policy {
	if len(policies) == 0 {
		return nil
	}
	out := make([]Policy, 0, len(policies))
	for _, p := range policies {
		ok, err := policyRequirementsMet(ctx, p, cfg)
		if err != nil {
			if logger != nil {
				logger.Debug("sca policy requirements error",
					"policy_id", p.Policy.ID,
					"error", err,
				)
			}
			continue
		}
		if !ok {
			if logger != nil {
				logger.Debug("sca policy skipped (requirements not met)",
					"policy_id", p.Policy.ID,
					"policy_name", p.Policy.Name,
				)
			}
			continue
		}
		out = append(out, p)
	}
	return out
}

func policyRequirementsMet(ctx context.Context, p Policy, cfg EvalConfig) (bool, error) {
	if p.Requirements == nil || len(p.Requirements.Rules) == 0 {
		return true, nil
	}
	cond := p.Requirements.Condition
	if cond == "" {
		cond = "all"
	}
	return evaluateCondition(ctx, cond, p.Requirements.Rules, cfg)
}
