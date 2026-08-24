package main

import "testing"

func TestInitialScreen(t *testing.T) {
	if got := initialScreen(false, false); got != screenEnroll {
		t.Fatalf("unenrolled = %v, want enroll", got)
	}
	if got := initialScreen(true, true); got != screenPreflight {
		t.Fatalf("enrolled+preflight = %v, want preflight", got)
	}
	if got := initialScreen(true, false); got != screenDash {
		t.Fatalf("enrolled = %v, want dashboard", got)
	}
}

func TestClassifyHealth(t *testing.T) {
	if classifyHealth(true, true, true, false) != healthSecure {
		t.Fatal("expected secure")
	}
	if classifyHealth(true, true, true, true) != healthContained {
		t.Fatal("expected contained")
	}
	if classifyHealth(true, true, false, false) != healthDegraded {
		t.Fatal("expected degraded")
	}
	if classifyHealth(false, false, false, false) != healthOffline {
		t.Fatal("expected offline")
	}
	if classifyHealth(true, false, false, false) != healthOffline {
		t.Fatal("enrolled but stopped should be offline")
	}
}
