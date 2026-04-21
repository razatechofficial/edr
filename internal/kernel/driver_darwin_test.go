//go:build darwin && cgo

package kernel

import (
	"testing"
	"time"

	"github.com/razatechofficial/edr/pkg/events"
)

func TestESFDriverName(t *testing.T) {
	t.Parallel()
	d := &ESFDriver{}
	if got := d.Name(); got != "esf" {
		t.Errorf("Name() = %q, want %q", got, "esf")
	}
}

func TestESFDriverCapabilities(t *testing.T) {
	t.Parallel()
	d := &ESFDriver{}
	caps := d.Capabilities()

	want := map[events.EventType]bool{
		events.EventProcess: true,
		events.EventFile:    true,
		events.EventMemory:  true,
		events.EventAuth:    true,
		events.EventModule:  true,
		events.EventMount:   true,
		events.EventSignal:  true,
		events.EventPtrace:  true,
	}

	if len(caps) != len(want) {
		t.Fatalf("Capabilities() returned %d types, want %d", len(caps), len(want))
	}
	for _, c := range caps {
		if !want[c] {
			t.Errorf("unexpected capability: %s", c)
		}
	}
}

func TestDecisionCacheHit(t *testing.T) {
	t.Parallel()
	c := newAuthCache(time.Minute)
	c.set("/usr/bin/malware", AuthDeny)

	decision, ok := c.get("/usr/bin/malware")
	if !ok {
		t.Fatal("expected cache hit")
	}
	if decision != AuthDeny {
		t.Errorf("decision = %v, want AuthDeny", decision)
	}
}

func TestDecisionCacheMiss(t *testing.T) {
	t.Parallel()
	c := newAuthCache(time.Minute)

	_, ok := c.get("/usr/bin/unknown")
	if ok {
		t.Fatal("expected cache miss for unknown entry")
	}
}

func TestDecisionCacheExpiry(t *testing.T) {
	c := newAuthCache(50 * time.Millisecond)
	c.set("/usr/bin/test", AuthDeny)

	decision, ok := c.get("/usr/bin/test")
	if !ok {
		t.Fatal("entry should be present before TTL")
	}
	if decision != AuthDeny {
		t.Errorf("decision = %v, want AuthDeny", decision)
	}

	time.Sleep(100 * time.Millisecond)

	_, ok = c.get("/usr/bin/test")
	if ok {
		t.Fatal("expected cache miss after TTL expiry")
	}
}

// TestMutePathMatching verifies mute path configuration via policy.
// Actual ESF muting requires the com.apple.developer.endpoint-security.client
// entitlement and root privileges, so we only test the Go-side configuration.
func TestMutePathMatching(t *testing.T) {
	t.Parallel()

	if len(defaultMutePaths) == 0 {
		t.Fatal("defaultMutePaths should not be empty")
	}
	for i, p := range defaultMutePaths {
		if p == "" {
			t.Errorf("defaultMutePaths[%d] is empty", i)
		}
	}

	d := &ESFDriver{
		policy: EventPolicy{
			MutePaths: []string{"/opt/custom/agent/", "/var/log/edr/"},
		},
		cache: newAuthCache(time.Minute),
	}

	if len(d.policy.MutePaths) != 2 {
		t.Errorf("MutePaths len = %d, want 2", len(d.policy.MutePaths))
	}
	if d.policy.MutePaths[0] != "/opt/custom/agent/" {
		t.Errorf("MutePaths[0] = %q, want %q", d.policy.MutePaths[0], "/opt/custom/agent/")
	}
}
