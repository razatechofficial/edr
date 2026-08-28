package main

import "testing"

func TestParseLaunchctlState(t *testing.T) {
	notRunning := "system/com.razatech.edr-agent = {\n\tactive count = 0\n\tstate = not running\n\n\tprogram = /usr/local/libexec/edr-agent.app/Contents/MacOS/edr-agent\n\t\tstate = active\n}\n"
	if got := parseLaunchctlState(notRunning); got != "not running" {
		t.Fatalf("got %q", got)
	}
	running := "system/com.razatech.edr-agent = {\n\tstate = running\n\t\tstate = active\n}\n"
	if got := parseLaunchctlState(running); got != "running" {
		t.Fatalf("got %q", got)
	}
}
