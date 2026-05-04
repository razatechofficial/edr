//go:build windows

package main

import "testing"

func TestAssertWindowsNetworkContract_TCPUserlandRequiresTCPOnlyNote(t *testing.T) {
	srcs := []map[string]any{
		{
			"name":   "network",
			"source": "iphlpapi_extended_tcp",
			"notes":  "Userland MIB snapshots active; TCP-only pillar; policy=auto",
		},
	}
	out := assertWindowsNetworkContract(srcs)
	if len(out) != 1 {
		t.Fatalf("len=%d want 1", len(out))
	}
	if out[0].Failed {
		t.Fatalf("unexpected failure: %+v", out[0])
	}
}

func TestAssertWindowsNetworkContract_DelegateRequiresDelegateHint(t *testing.T) {
	srcs := []map[string]any{
		{
			"name":   "network",
			"source": "etw_sysmon_delegate",
			"notes":  "network pillar defers to Sysmon/kernel streams",
		},
	}
	out := assertWindowsNetworkContract(srcs)
	if len(out) != 1 {
		t.Fatalf("len=%d want 1", len(out))
	}
	if out[0].Failed {
		t.Fatalf("unexpected failure: %+v", out[0])
	}
}
