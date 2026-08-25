package main

import "testing"

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
}

func TestClassifyInstallError(t *testing.T) {
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
