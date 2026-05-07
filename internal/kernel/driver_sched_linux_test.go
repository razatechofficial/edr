//go:build linux

package kernel

import (
	"encoding/binary"
	"encoding/json"
	"testing"
	"unsafe"
)

func TestProcessRecordSchedEventPolicyGate(t *testing.T) {
	t.Parallel()
	raw := make([]byte, unsafe.Sizeof(bpfSchedEvent{}))
	binary.LittleEndian.PutUint32(raw[0:4], bpfEvtSchedSwitch)
	se := (*bpfSchedEvent)(unsafe.Pointer(&raw[0]))
	se.Hdr.Type = bpfEvtSchedSwitch
	se.Hdr.PID = 7
	se.PrevPID = 1
	se.NextPID = 2
	se.CPU = 3
	se.RuntimeNs = 99

	buf := NewRingBuffer(8192)
	d := &EBPFDriver{agentID: "t", buf: buf, policy: EventPolicy{SchedEvents: false}}
	if err := d.processRecord(raw); err != nil {
		t.Fatal(err)
	}
	if b, _ := buf.TryRead(); b != nil {
		t.Fatalf("expected drop when SchedEvents false, got %d bytes", len(b))
	}

	d.policy.SchedEvents = true
	if err := d.processRecord(raw); err != nil {
		t.Fatal(err)
	}
	b, err := buf.TryRead()
	if err != nil || b == nil {
		t.Fatalf("expected json event: err=%v len=%d", err, len(b))
	}
	var env map[string]interface{}
	if err := json.Unmarshal(b, &env); err != nil {
		t.Fatal(err)
	}
	if env["operation"] != "sched_switch" {
		t.Fatalf("%v", env)
	}
}
