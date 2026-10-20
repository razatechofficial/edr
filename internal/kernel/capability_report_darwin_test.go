//go:build darwin && cgo && !nosec

package kernel

// macOS capability report tests for the cgo/ESF build.
//
// These do not start an ESF client: es_new_client needs root and the
// EndpointSecurity entitlement, neither of which a unit test has. What they do
// check is the part that is wrong independently of the entitlement — the
// category table, the event-type mapping, and that a driver which has not
// subscribed reports nothing as attached.

import "testing"

func TestDarwinCapabilityTableIsCanonical(t *testing.T) {
	if len(esfHookCategories) == 0 {
		t.Fatal("esfHookCategories is empty")
	}
	for hook, cats := range esfHookCategories {
		if len(cats) == 0 {
			t.Errorf("ESF event %q maps to an empty category list", hook)
		}
		for _, c := range cats {
			if !isCanonicalCapability(c) {
				t.Errorf("ESF event %q maps to %q, which is not in CanonicalCapabilityCategories", hook, c)
			}
		}
	}
	for hook := range esfConditionalHooks {
		if _, ok := esfHookCategories[hook]; !ok {
			t.Errorf("esfConditionalHooks lists %q but esfHookCategories does not; the reason would never be reported", hook)
		}
	}
}

// TestDarwinCapabilityForESFEventMapsSubscribedEvents asserts every ESF event
// type esf_subscribe_all subscribes unconditionally is classified into the
// category its entry in esfHookCategories claims.
//
// This binds three things that are written separately and must agree: the
// subscription list in C, the attachment names in esfHookCategories, and the
// runtime mapper the tracker calls. A mismatch means events arrive and are
// credited to the wrong row, or to none.
func TestDarwinCapabilityForESFEventMapsSubscribedEvents(t *testing.T) {
	if len(esfEventTypeValues) == 0 {
		t.Fatal("esfEventTypeValues is empty")
	}
	for name, raw := range esfEventTypeValues {
		want, ok := esfHookCategories[name]
		if !ok {
			t.Errorf("ESF event %s has a resolved value but no entry in esfHookCategories", name)
			continue
		}
		got := darwinCapabilityForESFEvent(raw)
		if got == "" {
			t.Errorf("darwinCapabilityForESFEvent(%s = %d) returned no category; events of this type would be credited to nothing and the category would read attached-but-silent", name, raw)
			continue
		}
		var matched bool
		for _, c := range want {
			if c == got {
				matched = true
				break
			}
		}
		if !matched {
			t.Errorf("darwinCapabilityForESFEvent(%s) = %q, but esfHookCategories[%s] = %v; the mapper and the table disagree", name, got, name, want)
		}
	}
}

func TestDarwinCapabilityReportUnsubscribedDriver(t *testing.T) {
	d := &ESFDriver{caps: newCapabilityTracker()}

	rep := d.CapabilityReport()
	if rep.Driver != "esf" {
		t.Errorf("driver = %q, want esf", rep.Driver)
	}
	if rep.DriverRunning {
		t.Error("driver_running should be false on a driver that never subscribed")
	}
	for _, c := range rep.Categories {
		if c.Attached {
			t.Errorf("category %q attached without an ESF subscription", c.Category)
		}
	}

	// Categories ESF genuinely cannot serve must be absent rather than
	// merely unattached, so the console does not show a macOS fleet as
	// having broken DNS or registry monitoring that was never possible.
	for _, cat := range []CapabilityCategory{CapNetworkDNS, CapRegistryWrite, CapScheduler, CapTLSMetadata, CapNetworkAccept, CapNetworkClose, CapModuleUnload, CapNamespaceChange, CapFilePermission} {
		c := findCapability(t, rep, cat)
		if c.Present {
			t.Errorf("category %q should be absent on the ESF driver", cat)
		}
	}

	// And ones it does serve must be present but stopped.
	for _, cat := range []CapabilityCategory{CapProcessExec, CapFileWrite, CapMount, CapPtrace} {
		c := findCapability(t, rep, cat)
		if !c.Present {
			t.Errorf("category %q should be present: ESF subscribes an event for it", cat)
		}
		if c.Derivation != DerivationDriverStopped {
			t.Errorf("category %q derivation = %q, want %q", cat, c.Derivation, DerivationDriverStopped)
		}
	}
}
