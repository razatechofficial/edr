//go:build windows

package kernel

// Windows capability report tests.
//
// The ETW driver can be constructed without elevation, so these drive a real
// driver value and seed the provider health records that startSessions would
// have written. That is the fact the report reads, so seeding it is a faithful
// stand-in for a run where some providers enabled and some did not — the state
// the report exists to surface, and the normal Windows failure mode.

import (
	"strings"
	"testing"
)

func TestWindowsCapabilityTableUsesKnownProviderNames(t *testing.T) {
	known := make(map[string]bool)
	for _, pc := range etwCoreProviders {
		known[pc.name] = true
	}
	for name := range etwHookCategories {
		if !known[name] {
			t.Errorf("etwHookCategories lists provider %q, which is not in etwCoreProviders.\n"+
				"The report matches providers by the name recordProviderHealth writes, so a name that is not in that table can never be reported attached.", name)
		}
	}
	for name := range etwHookCategories {
		for _, c := range etwHookCategories[name] {
			if !isCanonicalCapability(c) {
				t.Errorf("provider %q maps to %q, which is not in CanonicalCapabilityCategories", name, c)
			}
		}
	}
}

// TestWindowsCapabilityReportReflectsProviderHealth is the important one: a
// provider that failed to enable must come back unattached, carrying its own
// enable error, while its siblings stay attached.
func TestWindowsCapabilityReportReflectsProviderHealth(t *testing.T) {
	d, err := NewETWDriver("test-agent")
	if err != nil {
		t.Fatalf("NewETWDriver: %v", err)
	}
	d.running.Store(true)

	d.recordProviderHealth(etwProviderProcess, true, "")
	d.recordProviderHealth(etwProviderFile, true, "")
	d.recordProviderHealth(etwProviderRegistry, false, "ERROR_ACCESS_DENIED")
	// Network and DNS were never attempted, which is distinct from having
	// been attempted and failed.

	d.caps.observe(CapProcessExec)

	rep := d.CapabilityReport()
	if rep.Driver != "etw" {
		t.Errorf("driver = %q, want etw", rep.Driver)
	}

	exec := findCapability(t, rep, CapProcessExec)
	if !exec.Attached || !exec.Producing {
		t.Errorf("process_exec should be attached and producing, got %+v", exec)
	}
	if exec.Derivation != DerivationRuntimeProvider {
		t.Errorf("process_exec derivation = %q, want %q: ETW attach state is per provider, not per event", exec.Derivation, DerivationRuntimeProvider)
	}

	// Same provider, no events of this category yet.
	exit := findCapability(t, rep, CapProcessExit)
	if !exit.Attached {
		t.Error("process_exit should be attached: it shares the Process provider with process_exec")
	}
	if exit.Producing {
		t.Error("process_exit should not be producing: no ProcessStop event was observed")
	}

	reg := findCapability(t, rep, CapRegistryWrite)
	if !reg.Present {
		t.Error("registry_write should be present on Windows")
	}
	if reg.Attached {
		t.Error("registry_write must not be attached: its provider recorded an enable failure")
	}
	if reg.Reason == "" || !strings.Contains(reg.Reason, "ERROR_ACCESS_DENIED") {
		t.Errorf("registry_write reason = %q, want the provider's own enable error so an operator can act on it", reg.Reason)
	}

	net := findCapability(t, rep, CapNetworkConnect)
	if net.Attached {
		t.Error("network_connect must not be attached: its provider was never recorded as active")
	}

	// Categories Windows ETW does not serve at all.
	for _, cat := range []CapabilityCategory{CapScheduler, CapTLSMetadata, CapMount, CapNamespaceChange, CapCredentialChange} {
		c := findCapability(t, rep, cat)
		if c.Present {
			t.Errorf("category %q should be absent on Windows: no provider in the core set serves it", cat)
		}
		if c.Reason == "" {
			t.Errorf("category %q is absent with no reason", cat)
		}
	}
}

func TestWindowsCapabilityForETWEvent(t *testing.T) {
	cases := []struct {
		provider string
		eventID  uint16
		opcode   uint8
		want     CapabilityCategory
	}{
		{etwProviderProcess, 1, 0, CapProcessExec},
		{etwProviderProcess, 2, 0, CapProcessExit},
		{etwProviderProcess, 999, 0, ""},
		// Kernel-File event ids, measured on windows-latest: 12 Create,
		// 16 Write, 18/26 delete, 19/27 rename. 67/68 are the legacy
		// NT Kernel Logger FileIo read/write opcodes and mean nothing
		// to this provider.
		{etwProviderFile, kernelFileEvtWriteID, 0, CapFileWrite},
		{etwProviderFile, kernelFileEvtCreateID, 0, CapFileOpen},
		{etwProviderFile, kernelFileEvtSetDeleteID, 0, CapFileDelete},
		{etwProviderFile, kernelFileEvtDeletePathID, 0, CapFileDelete},
		{etwProviderFile, kernelFileEvtRenameID, 0, CapFileRename},
		{etwProviderFile, kernelFileEvtRenamePathID, 0, CapFileRename},
		{etwProviderFile, 67, 0, ""},
		{etwProviderFile, 68, 0, ""},
		// Kernel-Network: IPv4 TCP block at 10, IPv6 at 26, and the
		// opcode carries the same number as the event id. An Accept
		// (15) used to be credited to network_close by the legacy
		// opcode table.
		{etwProviderNetwork, kernelNetEvtConnect4, 12, CapNetworkConnect},
		{etwProviderNetwork, kernelNetEvtAccept4, 15, CapNetworkAccept},
		{etwProviderNetwork, kernelNetEvtDisconnect4, 13, CapNetworkClose},
		{etwProviderNetwork, kernelNetEvtConnect6, 28, CapNetworkConnect},
		{etwProviderNetwork, kernelNetEvtAccept6, 31, CapNetworkAccept},
		{etwProviderNetwork, kernelNetEvtDisconnect6, 29, CapNetworkClose},
		{etwProviderNetwork, kernelNetEvtSend4, 10, ""},
		{etwProviderNetwork, 0, 17, ""},
		{etwProviderDNS, 0, 0, CapNetworkDNS},
		{etwProviderRegistry, 0, 0, CapRegistryWrite},
		{"NotAProvider", 1, 0, ""},
	}
	for _, tc := range cases {
		got := windowsCapabilityForETWEvent(tc.provider, tc.eventID, tc.opcode)
		if got != tc.want {
			t.Errorf("windowsCapabilityForETWEvent(%q, %d, %d) = %q, want %q", tc.provider, tc.eventID, tc.opcode, got, tc.want)
		}
	}
}

func TestWindowsProviderNameForGUIDRoundTrips(t *testing.T) {
	for _, pc := range etwCoreProviders {
		if got := etwProviderNameForGUID(pc.guid); got != pc.name {
			t.Errorf("etwProviderNameForGUID(%v) = %q, want %q", pc.guid, got, pc.name)
		}
	}
}
