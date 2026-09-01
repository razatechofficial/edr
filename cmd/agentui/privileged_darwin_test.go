//go:build darwin

package main

import (
	"strings"
	"testing"
)

func TestShellCommandQuotesAppPath(t *testing.T) {
	got := shellCommand("/Applications/EDR Agent.app/Contents/MacOS/edrctl", []string{"enroll", "--token", "a b"})
	if !strings.HasPrefix(got, "'/Applications/EDR Agent.app/Contents/MacOS/edrctl' ") {
		t.Fatalf("binary must be quoted: %s", got)
	}
	if strings.Contains(got, "/Applications/EDR ") && !strings.Contains(got, "'/Applications/EDR Agent.app") {
		t.Fatalf("space in path would split for /bin/sh: %s", got)
	}
	if !strings.Contains(got, "'a b'") {
		t.Fatalf("args must be quoted: %s", got)
	}
}
