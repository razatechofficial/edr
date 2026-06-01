package agent

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/razatechofficial/edr/internal/config"
)

func TestControlPlanePolicyHashRoundTrip(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	a := &Agent{cfg: config.Config{}}
	a.cfg.Agent.DataDir = dir
	if err := a.saveControlPlanePolicyHash("abc123"); err != nil {
		t.Fatal(err)
	}
	if got := a.readControlPlanePolicyHash(); got != "abc123" {
		t.Fatalf("hash = %q want abc123", got)
	}
	path := a.controlPlanePolicyHashPath()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm()&0o077 != 0 {
		t.Fatalf("hash file mode too permissive: %o", info.Mode().Perm())
	}
}

func TestControlPlaneRulesRootFromYARA(t *testing.T) {
	t.Parallel()

	a := &Agent{cfg: config.Config{}}
	a.cfg.Detection.YARA.RulesDir = "/etc/edr-agent/rules/yara"
	root, err := a.controlPlaneRulesRoot()
	if err != nil {
		t.Fatal(err)
	}
	if root != "/etc/edr-agent/rules" {
		t.Fatalf("rules root = %q", root)
	}
}

func TestControlPlaneRulesRootFallback(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	a := &Agent{cfg: config.Config{}}
	a.cfg.Agent.DataDir = dir
	root, err := a.controlPlaneRulesRoot()
	if err != nil {
		t.Fatal(err)
	}
	want := filepath.Join(dir, "rules")
	if root != want {
		t.Fatalf("rules root = %q want %q", root, want)
	}
}
