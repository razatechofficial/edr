//go:build windows

package kernel

import (
	"errors"
	"strings"
	"testing"
)

func TestClassifyWFPEngineErr(t *testing.T) {
	t.Parallel()
	cases := []struct {
		code      uint32
		sys       error
		wantClass string
	}{
		{1722, nil, "transient"},
		{1753, nil, "transient"},
		{0, nil, "transient"},
		{0, errors.New("rpc"), "transient"},
		{42, nil, "permanent"},
		{42, errors.New("wrap"), "permanent"},
	}
	for _, tc := range cases {
		class, err := classifyWFPEngineErr(uintptr(tc.code), tc.sys)
		if class != tc.wantClass {
			t.Fatalf("code=%d sys=%v: class=%q want %q err=%v", tc.code, tc.sys, class, tc.wantClass, err)
		}
		if err == nil {
			t.Fatalf("code=%d: expected error", tc.code)
		}
	}
}

func TestWFPCtlRecoverOutcomeClassification(t *testing.T) {
	t.Parallel()
	w := NewWFPCtl()
	_ = w.Recover()
	h := w.Health()
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
