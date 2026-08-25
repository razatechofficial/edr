package uistate

import "testing"

func TestInitialScreen(t *testing.T) {
	if got := InitialScreen(false, false, false, false); got != Setup {
		t.Fatalf("not installed = %v, want setup", got)
	}
	if got := InitialScreen(true, false, false, false); got != Enroll {
		t.Fatalf("unenrolled = %v, want enroll", got)
	}
	if got := InitialScreen(true, true, true, false); got != Permissions {
		t.Fatalf("enrolled+grants = %v, want permissions", got)
	}
	if got := InitialScreen(true, true, false, false); got != Preflight {
		t.Fatalf("enrolled+stopped = %v, want preflight", got)
	}
	if got := InitialScreen(true, true, false, true); got != Dash {
		t.Fatalf("enrolled+running = %v, want dash", got)
	}
}

func TestClassifyHealth(t *testing.T) {
	if ClassifyHealth(true, true, true, false) != Protected {
		t.Fatal("expected protected")
	}
	if ClassifyHealth(true, true, true, true) != Contained {
		t.Fatal("expected contained")
	}
	if ClassifyHealth(true, true, false, false) != Degraded {
		t.Fatal("sensor up stream down is degraded")
	}
	if ClassifyHealth(true, false, false, false) != Unprotected {
		t.Fatal("stopped sensor is unprotected")
	}
	if ClassifyHealth(false, false, false, false) != Unprotected {
		t.Fatal("not enrolled is unprotected")
	}
}
