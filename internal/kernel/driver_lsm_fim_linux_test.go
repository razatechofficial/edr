//go:build linux

package kernel

import (
	"encoding/binary"
	"testing"
	"unsafe"
)

func TestProcessRecordLSMFimPolicyGate(t *testing.T) {
	t.Parallel()
	raw := make([]byte, unsafe.Sizeof(bpfFileEvent{}))
	binary.LittleEndian.PutUint32(raw[0:4], bpfEvtLSMFimUnlink)
	evt := (*bpfFileEvent)(unsafe.Pointer(&raw[0]))
	evt.Type = bpfEvtLSMFimUnlink
	evt.PID = 42
	copy(evt.Filename[:], "test\x00")

	buf := NewRingBuffer(8192)
	d := &EBPFDriver{agentID: "t", buf: buf, policy: EventPolicy{FileEvents: true, LSMFimEvents: false}}
	if err := d.processRecord(raw); err != nil {
		t.Fatal(err)
	}
	if b, _ := buf.TryRead(); b != nil {
		t.Fatalf("expected drop when LSMFimEvents false, got %d bytes", len(b))
	}

	d.policy.LSMFimEvents = true
	if err := d.processRecord(raw); err != nil {
		t.Fatal(err)
	}
	b, err := buf.TryRead()
	if err != nil || b == nil || len(b) < rawHeaderSize {
		t.Fatalf("expected raw event: err=%v len=%d", err, len(b))
	}
	if binary.LittleEndian.Uint16(b[0:2]) != bpfEvtLSMFimUnlink {
		t.Fatalf("type %d", binary.LittleEndian.Uint16(b[0:2]))
	}
}
