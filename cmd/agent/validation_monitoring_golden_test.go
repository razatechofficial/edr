package main

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"testing"

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

			rep := runMonitoringValidation(context.Background(), cfg)

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
