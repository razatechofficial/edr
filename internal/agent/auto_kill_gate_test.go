package agent

import (
	"testing"

	"github.com/razatechofficial/edr/internal/config"
	"github.com/razatechofficial/edr/internal/schema"
)

func gateAgent(allowlist []string, score int) *Agent {
	var cfg config.Config
	cfg.LegacyResponse.AllowKill = true
	cfg.LegacyResponse.AutoKillEnabled = true
	cfg.LegacyResponse.MinKillScore = score
	cfg.LegacyResponse.KillRuleAllowlist = allowlist
	return &Agent{cfg: cfg, killAllow: makeRuleAllowlist(allowlist)}
}

// The regression that mattered: an unset kill_rule_allowlist used to authorise
// every rule, and that is what the default configuration shipped. An operator
// who has not named the rules they trust has not authorised any of them.
func TestEmptyAllowlistAuthorisesNothing(t *testing.T) {
	a := gateAgent(nil, 90)
	al := schema.Alert{RuleID: "PROC-003", Score: 100}

	if a.shouldAutoKill(al) {
		t.Fatal("an empty kill_rule_allowlist authorised a termination")
	}
}

func TestOnlyAllowlistedRulesMayKill(t *testing.T) {
	a := gateAgent([]string{"PROC-003"}, 90)

	if !a.shouldAutoKill(schema.Alert{RuleID: "PROC-003", Score: 95}) {
		t.Error("an allowlisted rule above the threshold was refused")
	}
	if a.shouldAutoKill(schema.Alert{RuleID: "NET-012", Score: 100}) {
		t.Error("a rule that is not on the allowlist was permitted to kill")
	}
}

func TestScoreThresholdStillApplies(t *testing.T) {
	a := gateAgent([]string{"PROC-003"}, 95)
	if a.shouldAutoKill(schema.Alert{RuleID: "PROC-003", Score: 94}) {
		t.Error("a rule below the score threshold was permitted to kill")
	}
}

// Both master switches must independently stop everything.
func TestEitherMasterSwitchOffStopsAllKills(t *testing.T) {
	for _, tc := range []struct {
		name  string
		apply func(*config.Config)
	}{
		{"allow_kill off", func(c *config.Config) { c.LegacyResponse.AllowKill = false }},
		{"auto_kill_enabled off", func(c *config.Config) { c.LegacyResponse.AutoKillEnabled = false }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a := gateAgent([]string{"PROC-003"}, 90)
			tc.apply(&a.cfg)
			if a.shouldAutoKill(schema.Alert{RuleID: "PROC-003", Score: 100}) {
				t.Error("a termination was authorised with the switch off")
			}
		})
	}
}

// Anything that is not exactly "enforce" must observe, so a typo cannot arm
// the agent.
func TestOnlyExplicitEnforceEnforces(t *testing.T) {
	var cfg config.Config
	for _, mode := range []string{"", "observe", "Observe", "enforced", "enforce-later", "true", "yes"} {
		cfg.LegacyResponse.KillMode = mode
		if cfg.AutoKillEnforcing() {
			t.Errorf("kill_mode %q was treated as enforcing", mode)
		}
	}
	for _, mode := range []string{"enforce", "Enforce", " enforce "} {
		cfg.LegacyResponse.KillMode = mode
		if !cfg.AutoKillEnforcing() {
			t.Errorf("kill_mode %q was not treated as enforcing", mode)
		}
	}
}
