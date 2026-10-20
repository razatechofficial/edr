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

// TestEveryEvaluatorHonoursActive covers all four evaluation entry points, not
// just the network one.
//
// Engine has one rule loop per event family and each repeats the Active()
// check. Three of them had no test, so retiring a process, file or auth rule
// rested on four separate copies of two lines staying correct. A rule that
// cannot be retired is the worst kind of false positive: the operator does the
// documented thing, the alerts keep arriving, and the next thing they turn off
// is the alert channel.
//
// The table drives one disabled and one enabled rule per family through the
// matching evaluator with an event both would match, and asserts only the
// enabled one fires.
func TestEveryEvaluatorHonoursActive(t *testing.T) {
	off := false

	mk := func(id, eventType string, when rules.Condition) rules.Rule {
		return rules.Rule{ID: id, Name: id, Severity: "high", EventType: eventType, When: when}
	}
	disable := func(r rules.Rule) rules.Rule {
		r.ID += "-OFF"
		r.Name = r.ID
		r.Enabled = &off
		return r
	}

	cases := []struct {
		family   string
		rule     rules.Rule
		evaluate func(*Engine) []schema.Alert
	}{
		{
			family: "process",
			rule:   mk("PROC-ON", "process", rules.Condition{ChildIn: []string{"sh"}}),
			evaluate: func(e *Engine) []schema.Alert {
				return e.EvaluateProcess(schema.ProcessEvent{ProcessName: "sh", PID: 42})
			},
		},
		{
			family: "file",
			rule:   mk("FILE-ON", "file", rules.Condition{FilePathContains: []string{"/etc/shadow"}}),
			evaluate: func(e *Engine) []schema.Alert {
				return e.EvaluateFile(schema.FileEvent{Path: "/etc/shadow", Operation: "write"})
			},
		},
		{
			family: "network",
			rule:   mk("NET-ON", "network", rules.Condition{ProtocolIn: []string{"tcp"}}),
			evaluate: func(e *Engine) []schema.Alert {
				return e.EvaluateNetwork(schema.NetworkEvent{Protocol: "tcp", DestPt: 443})
			},
		},
		{
			family: "auth",
			rule:   mk("AUTH-ON", "auth", rules.Condition{OutcomeIn: []string{"failure"}}),
			evaluate: func(e *Engine) []schema.Alert {
				return e.EvaluateAuth(schema.AuthEvent{Outcome: "failure", User: "root"})
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.family, func(t *testing.T) {
			e := NewEngine(rules.RuleSet{Rules: []rules.Rule{disable(tc.rule), tc.rule}})
			alerts := tc.evaluate(e)
			if len(alerts) != 1 {
				t.Fatalf("%s: %d alerts, want only the enabled rule to fire: %+v", tc.family, len(alerts), alerts)
			}
			if alerts[0].RuleID != tc.rule.ID {
				t.Fatalf("%s: fired %q, want %q; the disabled rule was evaluated", tc.family, alerts[0].RuleID, tc.rule.ID)
			}
		})
	}
}
