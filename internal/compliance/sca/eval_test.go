package sca

import (
	"context"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
)

func TestEvaluateFileRule(t *testing.T) {
	t.Parallel()
	if runtime.GOOS != "linux" {
		t.Skip("ostype check requires linux /proc")
	}
	pass, err := evalFileRule("/proc/sys/kernel/ostype", "Linux")
	if err != nil {
		t.Fatal(err)
	}
	if !pass {
		t.Fatal("expected ostype Linux")
	}
}

func TestEvaluateCommandRuleModprobe(t *testing.T) {
	t.Parallel()
	if _, err := exec.LookPath("modprobe"); err != nil {
		t.Skip("modprobe not available")
	}
	ctx := context.Background()
	cfg := defaultEvalConfig()
	pass, err := evalCommandRule(ctx, "modprobe -n -v cramfs", "r:install /bin/false|install /bin/true|Module cramfs not found", cfg.CommandTimeout)
	if err != nil {
		t.Fatal(err)
	}
	if !pass {
		t.Log("modprobe pattern did not match; acceptable on hosts without cramfs module config")
	}
}

func TestLoadCISPolicyFixtures(t *testing.T) {
	t.Parallel()
	for _, name := range []string{"cis_amazon_linux_2023.yml", "cis_centos7_linux.yml"} {
		path := filepath.Join("..", "..", "..", "rules", "compliance", "sca", "linux", name)
		if _, err := loadPolicyFile(path); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
	}
}

func TestLoadPoliciesLinux(t *testing.T) {
	t.Parallel()
	if runtime.GOOS != "linux" {
		t.Skip("linux policy dir")
	}
	root := filepath.Join("..", "..", "..", "rules", "compliance", "sca")
	policies, err := LoadPolicies(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(policies) == 0 {
		t.Fatal("expected policies")
	}
}

func TestEvaluatePolicyRequirements(t *testing.T) {
	t.Parallel()
	p := Policy{
		Policy: PolicyMeta{ID: "test", Name: "test"},
		Requirements: &Requirements{
			Condition: "all",
			Rules:     []string{"f:/proc/sys/kernel/ostype -> Linux"},
		},
		Checks: []Check{
			{ID: 1, Name: "always", Condition: "all", Rules: []string{"f:/proc/sys/kernel/ostype -> Linux"}},
		},
	}
	if runtime.GOOS != "linux" {
		t.Skip("ostype requirement check requires linux")
	}
	summary := EvaluatePolicy(context.Background(), p, defaultEvalConfig())
	if summary.Passed != 1 {
		t.Fatalf("expected 1 passed, got %+v", summary)
	}
}
