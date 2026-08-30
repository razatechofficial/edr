package main

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestInstancePortNameSeparatesSetupFromConsole(t *testing.T) {
	setup := instancePortName(true)
	console := instancePortName(false)
	if setup == console {
		t.Fatal("Setup and the installed console must not share an instance lock")
	}
	if !strings.Contains(setup, "setup") {
		t.Fatalf("setup port %q", setup)
	}
	if !strings.Contains(console, "console") {
		t.Fatalf("console port %q", console)
	}
}

func TestInstancePortFileUsesTempDir(t *testing.T) {
	flagSetup = false
	p := instancePortFile()
	if filepath.Base(p) != instancePortName(false) {
		t.Fatalf("got %s", p)
	}
	flagSetup = true
	p = instancePortFile()
	if filepath.Base(p) != instancePortName(true) {
		t.Fatalf("got %s", p)
	}
	flagSetup = false
}
