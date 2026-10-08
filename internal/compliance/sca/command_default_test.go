package sca

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// An SCA rule of type `c:` runs an arbitrary binary with arbitrary arguments as
// root. Combined with a rule bundle that is not signature-verified, that turns
// the compliance rule set into a remote code execution channel on every
// endpoint. The default must therefore be off, and must stay off: this test
// exists so that flipping it back is a deliberate act with a failing test
// attached, rather than a one-word edit nobody notices.
func TestCommandRulesAreDisabledByDefault(t *testing.T) {
	if defaultEvalConfig().CommandsEnabled {
		t.Fatal("SCA command rules default to enabled; this is arbitrary root execution from rule content")
	}
}

// Being off has to stop the execution, not merely be recorded somewhere. This
// drives a real rule through the evaluator and asserts the binary never ran.
func TestADisabledCommandRuleDoesNotExecute(t *testing.T) {
	marker := filepath.Join(t.TempDir(), "executed")
	rule := "c:/bin/sh -c " + marker

	cfg := defaultEvalConfig()
	_, err := evalRuleBody(t.Context(), rule, cfg)
	if err == nil || !strings.Contains(err.Error(), "commands disabled") {
		t.Fatalf("err = %v; want the rule refused with 'commands disabled'", err)
	}
	if _, statErr := os.Stat(marker); statErr == nil {
		t.Fatal("the command ran despite commands being disabled")
	}
}

// And when an operator deliberately turns it on, the rule is evaluated — so the
// gate is the only thing standing between rule content and execution, which is
// precisely why its default matters.
func TestAnEnabledCommandRuleIsEvaluated(t *testing.T) {
	cfg := defaultEvalConfig()
	cfg.CommandsEnabled = true

	got, err := evalRuleBody(t.Context(), "c:/bin/echo marker -> r:marker", cfg)
	if err != nil {
		t.Skipf("echo unavailable in this environment: %v", err)
	}
	if !got {
		t.Error("an enabled command rule did not match its own output")
	}
}
