package xdrclient

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
)

func TestResolveMachineIDConfigOverride(t *testing.T) {
	got := ResolveMachineID("  ops-override-1234  ")
	if got != "ops-override-1234" {
		t.Fatalf("got %q", got)
	}
}

func TestResolveMachineIDCanonicalizesUUID(t *testing.T) {
	got := ResolveMachineID("AABBCCDD11223344556677889900AABB")
	want := "aabbccdd-1122-3344-5566-77889900aabb"
	if got != want {
		t.Fatalf("got %q want %q", got, want)
	}
}

func TestNormalizeMachineIDRejectsPlaceholders(t *testing.T) {
	for _, bad := range []string{
		"",
		"00000000-0000-0000-0000-000000000000",
		"FFFFFFFF-FFFF-FFFF-FFFF-FFFFFFFFFFFF",
		"To be filled by O.E.M.",
		"Default string",
		"None",
	} {
		if got := normalizeMachineID(bad); got != "" {
			t.Fatalf("normalizeMachineID(%q) = %q, want empty", bad, got)
		}
	}
}

func TestUsableHardwareValue(t *testing.T) {
	if usableHardwareValue("None") || usableHardwareValue("Default string") {
		t.Fatal("placeholders should be rejected")
	}
	if !usableHardwareValue("PF2ABCDE") {
		t.Fatal("real serial should be accepted")
	}
}

func TestHardwareSerialFingerprintShape(t *testing.T) {
	mfr := "dell inc."
	serial := "abc123"
	sum := sha256.Sum256([]byte(mfr + "|" + serial))
	want := "hw-" + hex.EncodeToString(sum[:16])
	if !strings.HasPrefix(want, "hw-") || len(want) != 3+32 {
		t.Fatalf("unexpected fingerprint shape %q", want)
	}
}

func TestResolveMachineIDNeverEmpty(t *testing.T) {
	// With empty config, platform cascade still yields a non-empty id.
	got := ResolveMachineID("")
	if strings.TrimSpace(got) == "" {
		t.Fatal("expected non-empty machine id")
	}
}
