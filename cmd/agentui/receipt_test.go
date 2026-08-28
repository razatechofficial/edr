package main

import (
	"errors"
	"testing"
)

func TestParseEnrollReceipt(t *testing.T) {
	raw := "time=2026-08-25T19:00:00Z level=INFO msg=enrolled\r\nenrolled agent_id=dev-abc machine_id=mid-1 secure_storage=keychain cert_not_after=2027-08-25T19:00:00Z\n"
	got := parseEnrollReceipt(raw)
	if got["agent_id"] != "dev-abc" || got["machine_id"] != "mid-1" {
		t.Fatalf("got %#v", got)
	}
	if got["cert_not_after"] != "2027-08-25T19:00:00Z" {
		t.Fatalf("cert %q", got["cert_not_after"])
	}
	if got["secure_storage"] != "keychain" {
		t.Fatalf("storage %q", got["secure_storage"])
	}
}

func TestParseEnrollReceiptCredentialsLoaded(t *testing.T) {
	got := parseEnrollReceipt("credentials loaded agent_id=a1 machine_id=m1 secure_storage=file cert_not_after=2027-01-02T03:04:05Z")
	if got["agent_id"] != "a1" || got["machine_id"] != "m1" {
		t.Fatalf("got %#v", got)
	}
}

func TestEnrollLooksSuccessfulFromStdout(t *testing.T) {
	out := "enrolled agent_id=dev-abc machine_id=mid-1 secure_storage=keychain cert_not_after=2027-08-25T19:00:00Z"
	if !enrollLooksSuccessful(out, errors.New("osascript: wrapper"), operatorStatus{}) {
		t.Fatal("stdout agent_id should count as enrolled even if the privilege wrapper reports an error")
	}
	if enrollLooksSuccessful("permission denied", errors.New("fail"), operatorStatus{}) {
		t.Fatal("failed enroll")
	}
}

func TestReceiptFromEnrollPrefersStdout(t *testing.T) {
	out := "enrolled agent_id=dev-abc machine_id=mid-1 secure_storage=keychain cert_not_after=2027-08-25T19:00:00Z"
	r := receiptFromEnroll(out, operatorStatus{})
	if r.DeviceID != "dev-abc" || r.MachineID != "mid-1" {
		t.Fatalf("receipt %#v", r)
	}
	if r.ValidUntil == "—" {
		t.Fatal("missing cert expiry")
	}
}
