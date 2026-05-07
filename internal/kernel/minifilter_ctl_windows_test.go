//go:build windows

package kernel

import (
	"encoding/binary"
	"strings"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
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
		t.Fatal("expected not-present error when port not connected")
	}
	if !strings.Contains(err.Error(), "not available") {
		t.Fatalf("unexpected err: %v", err)
	}
}

func TestBuildControlPlaneWireFraming(t *testing.T) {
	t.Parallel()
	payload := []byte("hello")
	wire, err := BuildControlPlaneWire(CmdSetConfig, payload)
	if err != nil {
		t.Fatal(err)
	}
	if len(wire) != 12+len(payload) {
		t.Fatalf("len %d want %d", len(wire), 12+len(payload))
	}
	if binary.LittleEndian.Uint16(wire[0:2]) != ControlPlaneFramingMagic {
		t.Fatalf("magic %04x", binary.LittleEndian.Uint16(wire[0:2]))
	}
	if binary.LittleEndian.Uint16(wire[2:4]) != ControlPlaneProtocolVersion {
		t.Fatalf("version %d", binary.LittleEndian.Uint16(wire[2:4]))
	}
	if binary.LittleEndian.Uint32(wire[4:8]) != uint32(CmdSetConfig) {
		t.Fatalf("cmd %08x", binary.LittleEndian.Uint32(wire[4:8]))
	}
	if binary.LittleEndian.Uint32(wire[8:12]) != uint32(len(payload)) {
		t.Fatalf("payload len field %d", binary.LittleEndian.Uint32(wire[8:12]))
	}
	if string(wire[12:]) != string(payload) {
		t.Fatalf("payload mismatch")
	}
}

func TestMinifilterCtl_SendFramingHeader(t *testing.T) {
	t.Parallel()
	old := filterSendMessageFn
	t.Cleanup(func() { filterSendMessageFn = old })

	filterSendMessageFn = func(hPort windows.Handle, inBuf uintptr, inLen uintptr, outBuf uintptr, outLen uintptr, bytesReturned uintptr) uintptr {
		if inBuf == 0 || inLen < 12 {
			t.Fatalf("bad send buffer")
		}
		s := unsafe.Slice((*byte)(unsafe.Pointer(inBuf)), inLen)
		if binary.LittleEndian.Uint16(s[0:2]) != ControlPlaneFramingMagic {
			t.Fatalf("magic")
		}
		if binary.LittleEndian.Uint32(s[8:12]) != 3 {
			t.Fatalf("payload len in wire")
		}
		return 0 // S_OK
	}

	m := NewMinifilterCtl(`\EdrPort`)
	m.h = windows.Handle(1) // synthetic; never CloseHandle in test
	m.state = "running"
	err := m.Send(CmdDriverStart, []byte("abc"))
	if err != nil {
		t.Fatal(err)
	}
	h := m.Health()
	if h["last_send_outcome"] != "ok" {
		t.Fatalf("health: %#v", h)
	}
}
