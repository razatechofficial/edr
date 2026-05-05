//go:build linux

package collector

import (
	"testing"

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
