package main

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/razatechofficial/edr/internal/collector"
	"github.com/razatechofficial/edr/internal/config"
)

func TestMonitoringHealthGolden_Fixtures(t *testing.T) {
	if testing.Short() && os.Getenv("EDR_MONITORING_GOLDEN") == "" {
		t.Skip("golden monitoring_health table; run without -short or set EDR_MONITORING_GOLDEN=1")
	}

	type goldenCase struct {
		fixture           string
		prepCfg           func(*config.Config)
		wantFailures      int
		wantSoftAssertion string
	}

	var cases []goldenCase
	switch runtime.GOOS {
	case "windows":
		cases = []goldenCase{
			{
				fixture: "testdata/monitoring_health/windows_userland_healthy.json",
				prepCfg: func(cfg *config.Config) {
					cfg.Monitoring.Mode = "userland"
					cfg.Monitoring.KernelEnabled = false
					cfg.Monitoring.RequireKernel = false
				},
				wantFailures: 0,
			},
			{
				fixture: "testdata/monitoring_health/windows_kernel_optional_absent.json",
				prepCfg: func(cfg *config.Config) {
					cfg.Monitoring.RequireKernel = false
					cfg.Monitoring.KernelEnabled = true
					cfg.Monitoring.Mode = "auto"
				},
				wantFailures: 0,
			},
		}
	default:
		cases = []goldenCase{
			{
				fixture: "testdata/monitoring_health/userland_healthy.json",
				prepCfg: func(cfg *config.Config) {
					cfg.Monitoring.Mode = "userland"
					cfg.Monitoring.KernelEnabled = false
					cfg.Monitoring.RequireKernel = false
				},
				wantFailures: 0,
			},
			{
				fixture: "testdata/monitoring_health/kernel_optional_absent.json",
				prepCfg: func(cfg *config.Config) {
					cfg.Monitoring.RequireKernel = false
					cfg.Monitoring.KernelEnabled = true
					cfg.Monitoring.Mode = "auto"
				},
				wantFailures: 0,
			},
			{
				fixture: "testdata/monitoring_health/stream_eps_rate_limited.json",
				prepCfg: func(cfg *config.Config) {
					cfg.Monitoring.Mode = "userland"
					cfg.Monitoring.KernelEnabled = false
					cfg.Monitoring.RequireKernel = false
				},
				wantFailures:      0,
				wantSoftAssertion: "rate_limit_drops.streaming_journal",
			},
		}
	}

	for _, tc := range cases {
		tc := tc
		t.Run(filepath.Base(tc.fixture), func(t *testing.T) {
			dir := t.TempDir()
			b, err := os.ReadFile(tc.fixture)
			if err != nil {
				t.Fatal(err)
			}
			var fixture map[string]any
			if err := json.Unmarshal(b, &fixture); err != nil {
				t.Fatalf("fixture %s invalid json: %v", tc.fixture, err)
			}
			if got, _ := fixture["schema_version"].(float64); int(got) != collector.MonitoringHealthSchemaVersion {
				t.Fatalf("fixture %s schema_version=%v want %d", tc.fixture, fixture["schema_version"], collector.MonitoringHealthSchemaVersion)
			}
			if err := os.WriteFile(filepath.Join(dir, "monitoring_health.json"), b, 0o644); err != nil {
				t.Fatal(err)
			}

			defs := config.Defaults()
			cfg := &defs
			cfg.Agent.DataDir = dir
			if tc.prepCfg != nil {
				tc.prepCfg(cfg)
				cfg.Agent.DataDir = dir
			}

			rep := runMonitoringValidation(context.Background(), cfg, false)

			gotFailed := int(rep.Failed)
			if gotFailed != tc.wantFailures {
				t.Fatalf("Failed=%d want %d assertions=%#v", rep.Failed, tc.wantFailures, rep.Assertions)
			}

			if tc.wantSoftAssertion == "" {
				return
			}
			var found bool
			for _, a := range rep.Assertions {
				if a.Name == tc.wantSoftAssertion && !a.Failed {
					found = true
					break
				}
			}
			if !found {
				t.Fatalf("missing soft assertion %q in %#v", tc.wantSoftAssertion, rep.Assertions)
			}
		})
	}
}

func TestMonitoringValidation_PlatformKernelContracts(t *testing.T) {
	cfg := config.Defaults()
	cfg.Monitoring.Mode = "auto"
	cfg.Monitoring.KernelEnabled = true

	switch runtime.GOOS {
	case "windows":
		sources := []map[string]any{
			{
				"name":                "kernel",
				"status":              "healthy",
				"control_plane_ready": true,
				"tamper": map[string]any{
					"signals": map[string]any{
						"etw_session_recover_attempts": float64(0),
					},
				},
			},
		}
		assertions := assertPlatformKernelContracts(sources, &cfg)
		for _, a := range assertions {
			if a.Failed {
				t.Fatalf("windows kernel contract failed: %+v", a)
			}
		}
		t.Run("control_plane_required", func(t *testing.T) {
			cfg2 := cfg
			cfg2.Monitoring.WindowsControlPlaneRequired = true
			cfg2.Monitoring.WindowsServiceHardening = true
			cfg2.Monitoring.WindowsWFPCtlProbe = true
			sources2 := []map[string]any{
				{
					"name":                "kernel",
					"status":              "healthy",
					"control_plane_ready": true,
					"service_hardening_posture": map[string]any{
						"applied":                    true,
						"failure_actions_configured": true,
					},
					"tamper": map[string]any{
						"signals": map[string]any{"x": true},
					},
				},
			}
			for _, a := range assertPlatformKernelContracts(sources2, &cfg2) {
				if a.Failed {
					t.Fatalf("windows required contract failed: %+v", a)
				}
			}
		})
	case "darwin":
		sources := []map[string]any{
			{
				"name":                 "kernel",
				"status":               "healthy",
				"esf_ingest_queue_cap": float64(4096),
				"ne_ctl": map[string]any{
					"network_extension_status": "running_scaffold",
				},
				"esf_revocation": map[string]any{
					"esf_revocation_status": "healthy",
					"esf_revocation_probes": map[string]any{
						"probe_sip": "System Integrity Protection status: enabled.",
					},
				},
				"tamper": map[string]any{
					"signals": map[string]any{
						"ne_degraded": false,
					},
				},
			},
		}
		assertions := assertPlatformKernelContracts(sources, &cfg)
		for _, a := range assertions {
			if a.Failed {
				t.Fatalf("darwin kernel contract failed: %+v", a)
			}
		}
	default:
		t.Skip("platform-specific contract test only for windows/darwin")
	}
}
