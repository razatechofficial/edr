//go:build windows

package kernel

import (
	"strings"
	"testing"
)

func TestClassifyFilterPortHR(t *testing.T) {
	t.Parallel()
	cases := []struct {
		hr        uint32
		wantClass string
	}{
		{0x800706BA, "transient"},
		{0x80070002, "permanent"},
		{0xDEADBEEF, "permanent"},
	}
	for _, tc := range cases {
		class, err := classifyFilterPortHR(tc.hr)
		if class != tc.wantClass {
			t.Fatalf("hr=%08x: class=%q want %q err=%v", tc.hr, class, tc.wantClass, err)
		}
		if err == nil {
			t.Fatalf("hr=%08x: expected error", tc.hr)
		}
	}
}

func TestMinifilterCtlRecoverOutcomeClassification(t *testing.T) {
	t.Parallel()
	m := NewMinifilterCtl(`\EdrPort`)
	if m == nil {
		t.Fatal("nil minifilter ctl")
	}
	_ = m.Recover()
	h := m.Health()
	outcome, _ := h["last_recover_outcome"].(string)
	if outcome == "" {
		t.Fatalf("missing recover outcome: %#v", h)
	}
	if !strings.HasPrefix(outcome, "recover_failed_") && outcome != "recovered" {
		t.Fatalf("unexpected recover outcome %q", outcome)
	}
	if _, ok := h["recoveries"]; !ok {
		t.Fatalf("expected recoveries counter: %#v", h)
	}
}

func TestMinifilterCtlSendSkeleton(t *testing.T) {
	t.Parallel()
	m := NewMinifilterCtl(`\EdrPort`)
	err := m.Send(CmdDriverStart, []byte("cfg"))
	if err == nil {
		t.Fatal("expected not-present error from skeleton send")
	}
}
