package main

import "testing"

func TestPreflightCanStart(t *testing.T) {
	ok := preflightItem{ID: "cert", State: checkOK}
	svcFail := preflightItem{ID: "svc", State: checkFail}
	certFail := preflightItem{ID: "cert", State: checkFail}
	if !preflightCanStart([]preflightItem{ok, ok}) {
		t.Fatal("all green should start")
	}
	if !preflightCanStart([]preflightItem{ok, svcFail}) {
		t.Fatal("missing service is repairable via Register and start")
	}
	if preflightCanStart([]preflightItem{certFail, svcFail}) {
		t.Fatal("cert fail must still block start")
	}
	if preflightCanStart(nil) {
		t.Fatal("empty checklist must not start")
	}
}

func TestServiceLooksMissing(t *testing.T) {
	for _, s := range []string{"", "unknown", "not installed", "Service missing"} {
		if !serviceLooksMissing(s) {
			t.Fatalf("%q should look missing", s)
		}
	}
	for _, s := range []string{"stopped", "installed", "running", "not running"} {
		if serviceLooksMissing(s) {
			t.Fatalf("%q should not look missing", s)
		}
	}
}

func TestServiceCheckStopped(t *testing.T) {
	ok, detail := serviceCheck(operatorStatus{Service: "stopped"})
	if !ok {
		t.Fatalf("stopped must count as registered: %s", detail)
	}
}
