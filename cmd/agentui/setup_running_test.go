package main

import (
	"strings"
	"testing"
)

func TestInstalledConsolePathMarkersExcludeSetup(t *testing.T) {
	for _, p := range installedConsolePathMarkers() {
		if strings.Contains(p, "EDR-Agent-Setup") {
			t.Fatalf("Setup must not be treated as the installed console: %s", p)
		}
	}
}

func TestConsoleOrSetupTCCSplit(t *testing.T) {
	// compiled via hostperm tests; keep a local sanity check on markers
	if len(installedConsolePathMarkers()) == 0 {
		t.Fatal("expected installed console markers")
	}
}
