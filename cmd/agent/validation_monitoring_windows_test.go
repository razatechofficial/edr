//go:build windows

package main

import (
	"testing"

	"github.com/razatechofficial/edr/internal/config"
)

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

func TestAssertWindowsETWThreatIntelContract_RequiresProbeWhenEnabled(t *testing.T) {
	cfg := config.Defaults()
	cfg.Monitoring.ETWThreatIntel = true
	out := assertWindowsETWThreatIntelContract([]map[string]any{
		{
			"name":                       "kernel",
			"etw_threat_intel_requested": true,
			"etw_threat_intel_probed":    true,
			"etw_threat_intel_ok":        false,
			"etw_threat_intel_status":    "disabled",
			"etw_threat_intel_reason":    "ppl_required",
		},
	}, &cfg)
	if len(out) != 1 || out[0].Failed {
		t.Fatalf("expected degraded-but-probed pass: %+v", out)
	}
}

func TestAssertWindowsETWThreatIntelContract_SkippedWhenDisabled(t *testing.T) {
	cfg := config.Defaults()
	out := assertWindowsETWThreatIntelContract(nil, &cfg)
	if len(out) != 0 {
		t.Fatalf("len=%d want 0", len(out))
	}
}
