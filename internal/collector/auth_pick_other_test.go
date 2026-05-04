//go:build !linux && !darwin && !windows

package collector

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/razatechofficial/edr/internal/config"
)

func TestPickRareOrPrimaryAuthFromPaths(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "auth.log")
	if err := os.WriteFile(p, []byte("sshd: test\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	var cfg config.Config
	cfg.Agent.DataDir = dir
	c := pickRareOrPrimaryAuthFromPaths(cfg, "ep", nil, []string{p})
	ac, ok := c.(*AuthCollector)
	if !ok {
		t.Fatalf("want *AuthCollector got %T", c)
	}
	if ac.logPath != p {
		t.Fatalf("logPath=%q want %q", ac.logPath, p)
	}
}
