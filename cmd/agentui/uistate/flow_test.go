package uistate

import "testing"

func TestInitialScreen(t *testing.T) {
	if got := InitialScreen(false, false); got != Enroll {
		t.Fatalf("unenrolled = %v, want enroll", got)
	}
	if got := InitialScreen(true, true); got != Preflight {
		t.Fatalf("enrolled+preflight = %v, want preflight", got)
	}
	if got := InitialScreen(true, false); got != Dash {
		t.Fatalf("enrolled = %v, want dashboard", got)
	}
}

func TestClassifyHealth(t *testing.T) {
	if ClassifyHealth(true, true, true, false) != Secure {
		t.Fatal("expected secure")
	}
	if ClassifyHealth(true, true, true, true) != Contained {
		t.Fatal("expected contained")
	}
	if ClassifyHealth(true, true, false, false) != Degraded {
		t.Fatal("expected degraded")
	}
	if ClassifyHealth(false, false, false, false) != Offline {
		t.Fatal("expected offline")
	}
	if ClassifyHealth(true, false, false, false) != Offline {
		t.Fatal("enrolled but stopped should be offline")
	}
}
