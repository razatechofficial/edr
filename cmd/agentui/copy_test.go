package main

import (
	"strings"
	"testing"
)

func TestInstalledBodyFor(t *testing.T) {
	if !strings.HasPrefix(installedBodyFor("macos"), "This Mac") {
		t.Fatal("macos")
	}
	if !strings.HasPrefix(installedBodyFor("windows"), "This PC") {
		t.Fatal("windows")
	}
	if !strings.Contains(installedBodyFor("linux"), "sudo edrctl enroll") {
		t.Fatal("linux")
	}
}

func TestInstallProgressHintFor(t *testing.T) {
	if !strings.Contains(installProgressHintFor("macos"), "LaunchDaemon") {
		t.Fatal("macos")
	}
	if !strings.Contains(installProgressHintFor("windows"), "Program Files") {
		t.Fatal("windows")
	}
	if !strings.Contains(installProgressHintFor("linux"), "machine-wide") {
		t.Fatal("linux")
	}
}

func TestSetupStepTitlesFor(t *testing.T) {
	m := setupStepTitlesFor("macos")
	if len(m) != 3 || m[2] != "Register LaunchDaemon" {
		t.Fatalf("macos = %#v", m)
	}
	w := setupStepTitlesFor("windows")
	if w[1] != "Install to Program Files" || w[2] != "Register EDRAgent service" {
		t.Fatalf("windows = %#v", w)
	}
	l := setupStepTitlesFor("linux")
	if l[1] != "Install deb/rpm package" || l[2] != "Register systemd unit" {
		t.Fatalf("linux = %#v", l)
	}
}

func TestSetupStepDoingFor(t *testing.T) {
	if !strings.Contains(setupStepDoingFor("macos", 2), "LaunchDaemon") {
		t.Fatal("macos doing")
	}
	if !strings.Contains(setupStepDoingFor("windows", 1), `Program Files\EDR Agent`) {
		t.Fatal("windows doing")
	}
	if !strings.Contains(setupStepDoingFor("linux", 2), "systemd") {
		t.Fatal("linux doing")
	}
	if setupStepDoingFor("macos", 9) != "Working…" {
		t.Fatal("oob")
	}
}
