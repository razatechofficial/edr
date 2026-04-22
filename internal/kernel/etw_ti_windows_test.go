//go:build windows

package kernel

import "testing"

func TestDecodeTIEventFrameOpcodes(t *testing.T) {
	for op := uint8(1); op <= 8; op++ {
		orig := TIEvent{
			Opcode:      op,
			CallerPID:   100 + uint32(op),
			TargetPID:   200 + uint32(op),
			BaseAddress: 0x1000 + uint64(op),
			RegionSize:  0x2000 + uint64(op),
			Protect:     0x20,
			ThreadID:    300 + uint32(op),
		}
		b := encodeTIEvent(orig)
		got, err := decodeTIEventFrame(b)
		if err != nil {
			t.Fatalf("opcode %d decode err: %v", op, err)
		}
		if got.Opcode != op || got.CallerPID != orig.CallerPID || got.TargetPID != orig.TargetPID {
			t.Fatalf("opcode %d mismatch: got %+v want %+v", op, got, orig)
		}
	}
}

func TestTIEnvelopeLSASSDetection(t *testing.T) {
	ev := TIEvent{Opcode: 7, CallerPID: 111, TargetPID: 222, Protect: 0x10}
	env := buildTIEnvelope(ev, "evil.exe", "lsass.exe")
	if env["type"] != "credential_access" {
		t.Fatalf("expected credential_access, got %v", env["type"])
	}
	if env["severity"] != "P0" {
		t.Fatalf("expected P0 severity, got %v", env["severity"])
	}
}

func TestRWXProtectDetection(t *testing.T) {
	if !isRWXProtect(0x40) {
		t.Fatal("0x40 must be RWX")
	}
	if !isRWXProtect(0x80) {
		t.Fatal("0x80 must be RWX")
	}
	if isRWXProtect(0x20) {
		t.Fatal("0x20 must not be RWX")
	}
}
