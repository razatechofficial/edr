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
