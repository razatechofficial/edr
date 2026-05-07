//go:build linux

package collector

import (
	"context"
	"encoding/binary"
	"testing"
	"time"

	"github.com/razatechofficial/edr/internal/schema"
)

func Test_parseAuditMsgSerial(t *testing.T) {
	body := `type=PATH msg=audit(1743524401.123:456): item=0 name="/etc/passwd"`
	if got := parseAuditMsgSerial(body); got != "456" {
		t.Fatalf("serial = %q want 456", got)
	}
}

func TestAuditSource_parseAuditBody_syscallPathCorrelates(t *testing.T) {
	a := NewAuditSource("ep1", "host1", nil, nil, false)

	syscallBody := `type=SYSCALL msg=audit(1743524401.123:789): arch=c000003e syscall=257 success=yes exit=3 pid=4242 uid=1000 euid=1000 comm="cat" exe="/bin/cat"`
	pathBody := `type=PATH msg=audit(1743524401.123:789): item=0 name="/tmp/secret" nametype=NORMAL`

	if a.parseAuditBody(1300, syscallBody) != nil {
		t.Fatal("expected syscall to buffer only")
	}
	ev := a.parseAuditBody(1302, pathBody)
	if ev == nil || ev.File == nil {
		t.Fatalf("expected FileEvent, got %+v", ev)
	}
	if ev.File.Path != "/tmp/secret" {
		t.Fatalf("path %q", ev.File.Path)
	}
	if ev.File.ActorPID != 4242 {
		t.Fatalf("pid %d", ev.File.ActorPID)
	}
	if ev.File.SubjectUID != "1000" {
		t.Fatalf("uid %q", ev.File.SubjectUID)
	}
	if ev.File.EventType != schema.EventFile {
		t.Fatalf("event type %v", ev.File.EventType)
	}
}

func Test_parseAuditKV_corpus(t *testing.T) {
	cases := []struct {
		body string
		want map[string]string
	}{
		{
			body: `type=PATH msg=audit(1.1:1): item=0 name="/tmp/my file.txt" nametype=NORMAL`,
			want: map[string]string{
				"type":     "PATH",
				"item":     "0",
				"name":     "/tmp/my file.txt",
				"nametype": "NORMAL",
			},
		},
		{
			body: `type=SYSCALL msg=audit(1.1:2): pid=1 auid=4294967295 uid=0 comm=62617368 exe=2F62696E2F62617368`,
			want: map[string]string{
				"type": "SYSCALL",
				"pid":  "1",
				"auid": "4294967295",
				"uid":  "0",
				"comm": "bash",
				"exe":  "/bin/bash",
			},
		},
		{
			body: `type=SYSCALL comm="quoted \"inner\" app" exe="/opt/foo bar/bin"`,
			want: map[string]string{
				"type": "SYSCALL",
				"comm": `quoted "inner" app`,
				"exe":  "/opt/foo bar/bin",
			},
		},
	}
	for _, tc := range cases {
		got := parseAuditKV(tc.body)
		for k, v := range tc.want {
			if got[k] != v {
				t.Fatalf("parseAuditKV(%q)[%q] = %q want %q (full=%v)", tc.body, k, got[k], v, got)
			}
		}
	}
}

func TestAuditSource_multiPATHSameSerial(t *testing.T) {
	a := NewAuditSource("ep1", "host1", nil, nil, false)
	syscallBody := `type=SYSCALL msg=audit(1743524401.123:999): pid=1111 uid=0 comm="sh" exe="/bin/sh"`
	path1 := `type=PATH msg=audit(1743524401.123:999): item=0 name="/a" nametype=PARENT`
	path2 := `type=PATH msg=audit(1743524401.123:999): item=1 name="/a/b" nametype=CREATE`
	if a.parseAuditBody(1300, syscallBody) != nil {
		t.Fatal("syscall should not emit")
	}
	ev1 := a.parseAuditBody(1302, path1)
	ev2 := a.parseAuditBody(1302, path2)
	if ev1 == nil || ev1.File == nil || ev1.File.Path != "/a" {
		t.Fatalf("ev1: %+v", ev1)
	}
	if ev2 == nil || ev2.File == nil || ev2.File.Path != "/a/b" {
		t.Fatalf("ev2: %+v", ev2)
	}
	if ev2.File.ActorPID != 1111 {
		t.Fatalf("second path lost actor pid: %d", ev2.File.ActorPID)
	}
}

func TestAuditSource_parseAndDispatch_DedupeSkipStillAdvances(t *testing.T) {
	a := NewAuditSource("ep1", "host1", nil, NewLinuxFileDeduper(time.Minute), false)
	const path = "/tmp/dup"
	if !a.fileDedupe.AllowWithSource(path, DedupeSourceAudit) {
		t.Fatal("failed to prime dedupe")
	}
	body := `type=PATH msg=audit(1743524401.123:789): item=0 name="` + path + `" nametype=NORMAL`
	msgLen := 16 + len(body)
	aligned := (msgLen + 3) &^ 3
	pkt := make([]byte, aligned)
	binary.LittleEndian.PutUint32(pkt[0:4], uint32(msgLen))
	binary.LittleEndian.PutUint16(pkt[4:6], uint16(1302)) // AUDIT_PATH
	copy(pkt[16:], []byte(body))

	ch := make(chan Telemetry, 1)
	sink := &StreamingSink{ch: ch}
	done := make(chan struct{})
	go func() {
		a.parseAndDispatch(context.Background(), pkt, sink)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(250 * time.Millisecond):
		t.Fatal("parseAndDispatch did not return; possible packet-advance stall")
	}
	select {
	case <-ch:
		t.Fatal("expected deduped event to be skipped")
	default:
	}
}
