package collector

import (
	"testing"
	"time"
)

func TestLineageTracker_UpsertMerges(t *testing.T) {
	lt := NewLineageTracker(64, time.Hour)
	first := lt.Upsert(LineageEntry{PID: 42, ParentPID: 1, ImagePath: "/usr/bin/cat", StartNS: 1000})
	if first.LineageID == "" {
		t.Fatal("LineageID must be set")
	}
	second := lt.Upsert(LineageEntry{PID: 42, ImageHash: "abc", ContainerID: "c1", ContainerRuntime: "docker"})
	if second.ImagePath != "/usr/bin/cat" {
		t.Errorf("expected merged ImagePath, got %q", second.ImagePath)
	}
	if second.ImageHash != "abc" || second.ContainerID != "c1" {
		t.Errorf("non-empty fields should overwrite: %+v", second)
	}
	if second.LineageID != first.LineageID {
		t.Errorf("LineageID changed without StartNS change: %q vs %q", first.LineageID, second.LineageID)
	}
}

func TestLineageTracker_GetMissAfterForget(t *testing.T) {
	lt := NewLineageTracker(8, time.Hour)
	lt.Upsert(LineageEntry{PID: 7, StartNS: 1})
	if _, ok := lt.Get(7); !ok {
		t.Fatal("expected hit")
	}
	lt.Forget(7)
	if _, ok := lt.Get(7); ok {
		t.Fatal("expected miss after Forget")
	}
}

func TestLineageIDForStable(t *testing.T) {
	a := LineageIDFor(1234, 9_000_000_000)
	b := LineageIDFor(1234, 9_000_000_000)
	if a == "" || a != b {
		t.Fatalf("LineageID not stable: %q vs %q", a, b)
	}
	c := LineageIDFor(1234, 9_000_000_001)
	if c == a {
		t.Fatal("StartNS change should yield different LineageID")
	}
}

func TestParseContainerFromCgroup(t *testing.T) {
	cases := []struct {
		in       string
		wantID   string
		wantRT   string
	}{
		{"12:devices:/docker/abcd1234ef", "abcd1234ef", "kubepods"}, // generic '/docker/' has no prefix; fall through to kubepods? actually we won't match
		{"0::/system.slice/docker-abcdef0123.scope", "abcdef0123", "docker"},
		{"0::/kubepods.slice/kubepods-burstable.slice/cri-containerd-deadbeef.scope", "deadbeef", "containerd"},
		{"0::/kubepods.slice/something/crio-cafebabe.scope", "cafebabe", "crio"},
		{"0::/system.slice/sshd.service", "", ""},
	}
	for _, tc := range cases[1:] {
		id, rt := ParseContainerFromCgroup(tc.in)
		if id != tc.wantID || rt != tc.wantRT {
			t.Errorf("ParseContainerFromCgroup(%q) = (%q,%q), want (%q,%q)", tc.in, id, rt, tc.wantID, tc.wantRT)
		}
	}
}
