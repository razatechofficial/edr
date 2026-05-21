//go:build linux

package collector

import "testing"

func TestAnalyzePostureProbesRootkitIOC(t *testing.T) {
	t.Parallel()
	findings := AnalyzePostureProbes(map[string]any{
		"rootkit_iocs": map[string]any{"ioc_hits": 2, "paths": []string{"/dev/.udev"}},
	})
	if len(findings) != 1 || findings[0].ProbeID != "rootkit_iocs" {
		t.Fatalf("findings=%+v", findings)
	}
}

func TestAnalyzePostureProbesLdPreloadChanged(t *testing.T) {
	t.Parallel()
	findings := AnalyzePostureProbes(map[string]any{
		"ld_so_preload_hash": map[string]any{"changed": true, "sha256": "abc"},
	})
	if len(findings) != 1 {
		t.Fatalf("findings=%+v", findings)
	}
}

func TestAnalyzePostureProbesNoFinding(t *testing.T) {
	t.Parallel()
	findings := AnalyzePostureProbes(map[string]any{
		"rootkit_iocs": map[string]any{"ioc_hits": 0},
	})
	if len(findings) != 0 {
		t.Fatalf("findings=%+v", findings)
	}
}
