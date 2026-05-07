//go:build windows

package kernel

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"strings"
	"testing"

	"golang.org/x/sys/windows"
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

func TestWFPCtl_SendMirrorFraming(t *testing.T) {
	t.Parallel()
	w := NewWFPCtl()
	w.h = windows.Handle(1)
	w.state = "running"
	payload := []byte{0x01, 0x02}
	err := w.SendMirror(CmdUpdateRules, payload)
	if err != nil {
		t.Fatal(err)
	}
	h := w.Health()
	if h["last_mirror_send_outcome"] != "framed" {
		t.Fatalf("health: %#v", h)
	}
	want, err := BuildControlPlaneWire(CmdUpdateRules, payload)
	if err != nil {
		t.Fatal(err)
	}
	prefixHex, _ := h["last_mirror_frame_prefix_hex"].(string)
	got, err := hex.DecodeString(prefixHex)
	if err != nil {
		t.Fatal(err)
	}
	n := 16
	if len(want) < n {
		n = len(want)
	}
	if len(got) != n {
		t.Fatalf("prefix len %d want %d", len(got), n)
	}
	if !strings.EqualFold(hex.EncodeToString(want[:n]), prefixHex) {
		t.Fatalf("prefix mismatch got %s want %s", prefixHex, hex.EncodeToString(want[:n]))
	}
	if binary.LittleEndian.Uint16(got[0:2]) != ControlPlaneFramingMagic {
		t.Fatalf("magic")
	}
}
