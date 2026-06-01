package rules

import (
	"os"
	"path/filepath"
	"testing"

	sigma "github.com/bradleyjkemp/sigma-go"
	"go.uber.org/zap"
)

func TestSigmaRuleAppliesToHost(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		rule sigma.Rule
		path string
		host string
		want bool
	}{
		{
			name: "macos path on macos",
			rule: sigma.Rule{Logsource: sigma.Logsource{Product: "macos"}},
			path: "macos/esf/exec.yml",
			host: "macos",
			want: true,
		},
		{
			name: "macos path on linux",
			rule: sigma.Rule{Logsource: sigma.Logsource{Product: "macos"}},
			path: "macos/esf/exec.yml",
			host: "linux",
			want: false,
		},
		{
			name: "windows product on linux",
			rule: sigma.Rule{Logsource: sigma.Logsource{Product: "windows", Category: "registry_set"}},
			path: "registry/run_key.yml",
			host: "linux",
			want: false,
		},
		{
			name: "cross platform no product",
			rule: sigma.Rule{Logsource: sigma.Logsource{Category: "network_connection"}},
			path: "network/beacon.yml",
			host: "linux",
			want: true,
		},
		{
			name: "linux product on linux",
			rule: sigma.Rule{Logsource: sigma.Logsource{Product: "linux", Category: "file_event"}},
			path: "persistence/cron.yml",
			host: "linux",
			want: true,
		},
		{
			name: "linux subdir on windows",
			rule: sigma.Rule{Logsource: sigma.Logsource{Category: "file_event"}},
			path: "linux/persistence/cron.yml",
			host: "windows",
			want: false,
		},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := sigmaRuleAppliesToHost(tc.rule, tc.path, tc.host)
			if got != tc.want {
				t.Fatalf("sigmaRuleAppliesToHost()=%v want %v", got, tc.want)
			}
		})
	}
}

func TestSigmaEngineLoadRulesPlatformFilter(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	macosDir := filepath.Join(dir, "macos")
	if err := os.MkdirAll(macosDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(macosDir, "mac_rule.yml"), []byte(`title: Mac Only
id: mac-only-001
level: low
logsource:
  product: macos
  category: process_creation
detection:
  selection:
    Image|endswith: /curl
  condition: selection
`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "generic.yml"), []byte(`title: Generic Net
id: generic-net-001
level: low
logsource:
  category: network_connection
detection:
  selection:
    DestinationPort: 443
  condition: selection
`), 0o644); err != nil {
		t.Fatal(err)
	}

	logger, _ := zap.NewDevelopment()
	engine, err := NewSigmaEngine(dir, logger)
	if err != nil {
		t.Fatalf("NewSigmaEngine: %v", err)
	}
	defer engine.Stop()

	host := sigmaHostProduct()
	count := engine.Count()
	switch host {
	case "macos":
		if count != 2 {
			t.Fatalf("Count()=%d want 2 on macos host", count)
		}
	default:
		if count != 1 {
			t.Fatalf("Count()=%d want 1 on %s host (mac-only rule skipped)", count, host)
		}
	}
}
