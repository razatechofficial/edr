package main

import "testing"

func TestSeverityAtLeast(t *testing.T) {
	t.Parallel()
	if !severityAtLeast("high", "medium") {
		t.Fatalf("expected high >= medium")
	}
	if severityAtLeast("low", "high") {
		t.Fatalf("expected low < high")
	}
}
