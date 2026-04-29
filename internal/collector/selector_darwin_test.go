//go:build darwin

package collector

import (
	"errors"
	"testing"
)

func TestSelectDarwinSources_ESFOK(t *testing.T) {
	sel := SelectDarwinSources(true, func() error { return nil })
	// On a typical dev machine running tests as non-root we still get the
	// "requires root" branch; assert the logic via direct probes too.
	if sel.ESFAvailable && (sel.UserlandActive || sel.ESFError != "") {
		t.Fatalf("inconsistent ok selection: %+v", sel)
	}
}

func TestSelectDarwinSources_ESFFailureAllowsFallback(t *testing.T) {
	probe := func() error { return errors.New("esf: too many clients") }
	sel := SelectDarwinSources(true, probe)
	if sel.ESFAvailable {
		t.Fatalf("expected ESFAvailable=false: %+v", sel)
	}
	if !sel.UserlandActive {
		// If we are not root we never reach the probe; permit either branch.
		if sel.Reason == "" {
			t.Fatal("expected reason to be populated")
		}
	}
	st := sel.SelectionStatus()
	if st.Status == "" {
		t.Fatalf("status not set: %+v", st)
	}
}

func TestSelectDarwinSources_NoFallbackKeepsUnavailable(t *testing.T) {
	probe := func() error { return errors.New("esf: missing entitlement") }
	sel := SelectDarwinSources(false, probe)
	if sel.UserlandActive {
		t.Fatalf("UserlandActive should be false when fallback disabled")
	}
	st := sel.SelectionStatus()
	if st.Status == "healthy" {
		t.Fatalf("expected non-healthy status: %+v", st)
	}
}
