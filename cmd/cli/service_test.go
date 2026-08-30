package main

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestSensorBinaryCandidatesIncludeSystemPaths(t *testing.T) {
	got := strings.Join(sensorBinaryCandidates(), "\n")
	for _, want := range []string{
		"/usr/local/bin/edr-agent",
		"/Library/Application Support/EDR/bin/edr-agent",
		"/usr/local/libexec/edr-agent.app/Contents/MacOS/edr-agent",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("missing %s in %q", want, got)
		}
	}
}

func TestIsSiblingOfSelf(t *testing.T) {
	if isSiblingOfSelf("/usr/local/bin/edr-agent") {
		t.Fatal("system path must not count as sibling of this test binary")
	}
	if isSiblingOfSelf(filepath.Join(t.TempDir(), "edr-agent")) {
		t.Fatal("unrelated dir")
	}
}
