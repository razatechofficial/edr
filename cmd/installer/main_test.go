package main

import "testing"

func TestBinaryNames(t *testing.T) {
	t.Parallel()
	if agentBinaryName() == "" || edrctlBinaryName() == "" {
		t.Fatalf("binary names must not be empty")
	}
}
