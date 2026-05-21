package config

import (
	"runtime"
	"testing"
)

func TestApplyComplianceDefaultsPostureProbes(t *testing.T) {
	t.Parallel()
	cfg := Defaults()
	cfg.Compliance.Enabled = true
	cfg.Monitoring.PostureProbes = nil
	cfg.Monitoring.PostureEnabled = false
	ApplyComplianceDefaults(&cfg)
	if !cfg.Monitoring.PostureEnabled {
		t.Fatal("expected posture enabled")
	}
	if len(cfg.Monitoring.PostureProbes) == 0 {
		t.Fatal("expected default posture probes")
	}
}

func TestApplyComplianceDefaultsRespectsDisabledPosture(t *testing.T) {
	t.Parallel()
	cfg := Defaults()
	cfg.Compliance.Enabled = true
	cfg.Compliance.EnablePosture = false
	cfg.Monitoring.PostureProbes = []string{"custom_probe"}
	ApplyComplianceDefaults(&cfg)
	if len(cfg.Monitoring.PostureProbes) != 1 || cfg.Monitoring.PostureProbes[0] != "custom_probe" {
		t.Fatalf("probes=%v", cfg.Monitoring.PostureProbes)
	}
}

func TestApplyComplianceDefaultsRootcheckLinux(t *testing.T) {
	t.Parallel()
	if runtime.GOOS != "linux" {
		t.Skip("linux rootcheck flag")
	}
	cfg := Defaults()
	cfg.Compliance.Enabled = true
	ApplyComplianceDefaults(&cfg)
	if !cfg.Monitoring.LinuxRootcheckEnabled {
		t.Fatal("expected rootcheck enabled")
	}
}
