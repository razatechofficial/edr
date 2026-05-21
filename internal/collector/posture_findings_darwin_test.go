//go:build darwin

package collector

import "testing"

func TestAnalyzeDarwinPostureProbesGatekeeperDisabled(t *testing.T) {
	findings := AnalyzeDarwinPostureProbes(map[string]any{
		"posture_darwin_gatekeeper": map[string]any{
			"spctl_status": "assessments disabled",
		},
	})
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
}

func TestAnalyzeDarwinPostureProbesNoFinding(t *testing.T) {
	findings := AnalyzeDarwinPostureProbes(map[string]any{
		"posture_darwin_gatekeeper": map[string]any{
			"spctl_status": "assessments enabled",
		},
	})
	if len(findings) != 0 {
		t.Fatalf("expected no findings, got %d", len(findings))
	}
}
