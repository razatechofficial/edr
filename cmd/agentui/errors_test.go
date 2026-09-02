package main

import (
	"strings"
	"testing"
)

func TestClassifyEnrollError(t *testing.T) {
	if classifyEnrollError("dial enrollment: i/o timeout").Title != "Can’t reach the enrollment service" {
		t.Fatal("timeout")
	}
	if classifyEnrollError("enrollment rejected: token expired").Title != "This token has expired" {
		t.Fatal("expired")
	}
	if classifyEnrollError("enrollment rejected: invalid token").Title != "This token was not accepted" {
		t.Fatal("invalid")
	}
	if classifyEnrollError("keychain: item add failed").Title != "Could not store the device certificate" {
		t.Fatal("keystore")
	}
	if classifyStartError("sensor did not stay running (status not running)").Title != "The sensor could not start" {
		t.Fatal("start running")
	}
	if isDarwin() && !strings.Contains(classifyStartError("sensor did not stay running (status loaded)").Body, "Full Disk Access") {
		t.Fatal("fda start copy")
	}
	if !strings.Contains(classifyStartError("local sensor binary not found next to edrctl").Body, "Reinstall the EDR Agent package") {
		t.Fatal("missing sensor copy")
	}
	if !serviceAlreadyPresentError("register EDRAgent service: The specified service already exists.") {
		t.Fatal("already exists")
	}
	if classifyStartError("register EDRAgent service: The specified service already exists.").Title != "The sensor service is already registered" {
		t.Fatal("already exists copy")
	}
}

func TestClassifyInstallError(t *testing.T) {
	if classifyInstallError("Operation did not complete successfully because the file contains a virus or potentially unwanted software.").Title != "Windows blocked this installer" {
		t.Fatal("defender")
	}
	if classifyInstallError("agent binary not found").Title != "Setup could not find the agent files" {
		t.Fatal("missing agent")
	}
	if classifyInstallError("no space left on device").Title != "Not enough disk space" {
		t.Fatal("disk")
	}
	if classifyInstallError("root privileges required").Title != "Administrator rights required" {
		t.Fatal("admin")
	}
}

func TestIdentityStepIndex(t *testing.T) {
	if got := identityStepIndex("csr"); got != 2 {
		t.Fatalf("csr = %d", got)
	}
	if got := identityStepIndex("done"); got != 6 {
		t.Fatalf("done = %d", got)
	}
	if got := identityStepIndex("nope"); got != -1 {
		t.Fatalf("unknown = %d", got)
	}
}

func TestCertExpiring(t *testing.T) {
	ok, _ := certExpiring("")
	if ok {
		t.Fatal("blank")
	}
}

func TestFormatBytesMB(t *testing.T) {
	if formatBytesMB(512) == "" {
		t.Fatal("empty")
	}
}

func TestServiceHealthy(t *testing.T) {
	if serviceHealthy("not running") {
		t.Fatal(`"not running" must not count as healthy`)
	}
	if serviceHealthy("inactive") {
		t.Fatal("inactive")
	}
	if serviceHealthy("loaded") {
		t.Fatal("loaded is registered, not running")
	}
	if !serviceHealthy("running") {
		t.Fatal("running")
	}
	if !serviceHealthy("active") {
		t.Fatal("active")
	}
}
