package main

import "testing"

func TestRunOneCheckCert(t *testing.T) {
	ok, _ := runOneCheck("cert", operatorStatus{})
	if ok {
		t.Fatal("unenrolled host should fail cert check")
	}
	ok, detail := runOneCheck("cert", operatorStatus{AgentID: "dev-1"})
	if !ok {
		t.Fatalf("session identity should pass: %s", detail)
	}
	ok, detail = runOneCheck("cert", operatorStatus{Enrolled: true, AgentID: "dev-1"})
	if !ok {
		t.Fatalf("enrolled should pass: %s", detail)
	}
}

func TestRunOneCheckSvcNotLoaded(t *testing.T) {
	ok, detail := runOneCheck("svc", operatorStatus{Service: "not loaded"})
	if !ok {
		t.Fatalf("not loaded should still count as installed: %s", detail)
	}
}
