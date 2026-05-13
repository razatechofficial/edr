//go:build linux

package collector

import (
	"context"
	"testing"

	"github.com/razatechofficial/edr/internal/config"
)

func TestUpdateLinuxProcNetEnrichStats_LowRateStreak(t *testing.T) {
	nc := &NetworkCollector{}
	nc.cfg.Monitoring.LinuxProcNetPIDEnrich = true
	connsLow := make([]connEntry, 10)
	for i := range connsLow {
		connsLow[i] = connEntry{inode: uint64(i + 1), pid: 0}
	}
	for i := 0; i < 6; i++ {
		updateLinuxProcNetEnrichStats(nc, connsLow)
	}
	if v := nc.linuxEnrichLowRateStreak.Load(); v < 6 {
		t.Fatalf("low rate streak=%d want >=6", v)
	}
	connsHit := make([]connEntry, 10)
	for i := range connsHit {
		connsHit[i] = connEntry{inode: uint64(i + 1), pid: int(i + 1)}
	}
	updateLinuxProcNetEnrichStats(nc, connsHit)
	if nc.linuxEnrichLowRateStreak.Load() != 0 {
		t.Fatalf("streak=%d want 0 after full PID hits", nc.linuxEnrichLowRateStreak.Load())
	}
}

func TestExportMonitoringHealth_PIDAttributionRate(t *testing.T) {
	nc := NewNetworkCollector("e1", config.Config{})
	nc.cfg.Monitoring.LinuxProcNetPIDEnrich = true
	nc.linuxEnrichInodeLast.Store(100)
	nc.linuxEnrichPIDLast.Store(1)
	nc.linuxEnrichLowRateStreak.Store(6)
	m := nc.ExportMonitoringHealth()
	if _, ok := m["pid_attribution_rate"]; !ok {
		t.Fatal("missing pid_attribution_rate")
	}
	if m["auto_promotion_hint"] != "enable_linux_pid_network" {
		t.Fatalf("auto_promotion_hint=%v", m["auto_promotion_hint"])
	}
}

func TestApplyLinuxProcNetPIDEnrichIfConfigured_NoOpWhenDisabled(t *testing.T) {
	nc := NewNetworkCollector("e1", config.Config{})
	nc.cfg.Monitoring.LinuxProcNetPIDEnrich = false
	conns := []connEntry{{inode: 1, pid: 0}}
	applyLinuxProcNetPIDEnrichIfConfigured(context.Background(), nc, conns)
	if nc.linuxEnrichInodeLast.Load() != 0 {
		t.Fatal("expected no inode stats when enrich disabled")
	}
}
