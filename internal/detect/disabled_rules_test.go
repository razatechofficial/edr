package detect

import (
	"testing"

	"github.com/razatechofficial/edr/internal/rules"
	"github.com/razatechofficial/edr/internal/schema"
)

// A rule whose condition cannot express what its name claims is worse than no
// rule: it fires constantly and teaches analysts to ignore alerts. Retiring it
// has to actually stop it being evaluated.
func TestADisabledRuleIsNotEvaluated(t *testing.T) {
	off := false
	rs := rules.RuleSet{Rules: []rules.Rule{
		{
			ID:        "NET-OFF",
			Name:      "Disabled network rule",
			Severity:  "high",
			EventType: "network",
			Enabled:   &off,
			When:      rules.Condition{ProtocolIn: []string{"tcp"}},
		},
		{
			ID:        "NET-ON",
			Name:      "Active network rule",
			Severity:  "high",
			EventType: "network",
			When:      rules.Condition{ProtocolIn: []string{"tcp"}},
		},
	}}

	e := NewEngine(rs)
	alerts := e.EvaluateNetwork(schema.NetworkEvent{Protocol: "tcp", DestPt: 443})

	if len(alerts) != 1 {
		t.Fatalf("%d alerts, expected only the active rule to fire: %+v", len(alerts), alerts)
	}
	if alerts[0].RuleID != "NET-ON" {
		t.Fatalf("fired rule %q, expected NET-ON", alerts[0].RuleID)
	}
}

// Absent means enabled, so every existing rule file keeps its behaviour.
func TestARuleWithoutTheFieldStaysActive(t *testing.T) {
	if !(rules.Rule{}).Active() {
		t.Fatal("a rule with no enabled field was treated as disabled")
	}
	on := true
	if !(rules.Rule{Enabled: &on}).Active() {
		t.Fatal("an explicitly enabled rule was treated as disabled")
	}
	off := false
	if (rules.Rule{Enabled: &off}).Active() {
		t.Fatal("an explicitly disabled rule was treated as active")
	}
}
