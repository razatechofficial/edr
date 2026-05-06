package collector

import (
	"testing"

	"github.com/razatechofficial/edr/internal/config"
)

func TestEffectiveLogTargetsMigratesAdditionalPaths(t *testing.T) {
	t.Parallel()
	var cfg config.Config
	cfg.Monitoring.AdditionalLogTailPaths = []string{"/var/log/a.log", "/var/log/a.log", ""}
	got := EffectiveLogTargets(cfg)
	if len(got) != 1 || got[0].Type != "file" || got[0].Path != "/var/log/a.log" {
		t.Fatalf("got %#v", got)
	}
	cfg.Monitoring.AdditionalLogTailPaths = nil
	cfg.Monitoring.LogTargets = []config.LogTarget{{Type: "FILE", Path: "/x", Query: "q1"}}
	cfg2 := cfg
	cfg2.Monitoring.LogTargets = append(cfg2.Monitoring.LogTargets, config.LogTarget{Type: "file", Path: "/x", Query: "q1"})
	got2 := EffectiveLogTargets(cfg2)
	if len(got2) != 1 {
		t.Fatalf("dedupe failed: %#v", got2)
	}
}

func TestLogTargetsCollectorHealthRows(t *testing.T) {
	t.Parallel()
	var cfg config.Config
	cfg.Service.EndpointID = "e1"
	cfg.Monitoring.LogTargets = []config.LogTarget{{Type: "file", Path: "/nope"}}
	lt := NewLogTargetsCollector(cfg)
	if lt == nil {
		t.Fatal("expected collector")
	}
	rows := lt.ExportMonitoringHealthRows()
	if len(rows) != 1 {
		t.Fatalf("rows=%d", len(rows))
	}
	if rows[0]["name"] != "log_target.0" {
		t.Fatalf("%v", rows[0])
	}
}
