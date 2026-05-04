//go:build linux

package collector

import "testing"

func TestUpdateLinuxProcNetEnrichMiss(t *testing.T) {
	nc := &NetworkCollector{}
	nc.cfg.Monitoring.LinuxProcNetPIDEnrich = true
	nc.linuxEnrichMissStreak.Store(0)
	updateLinuxProcNetEnrichMiss(nc, []connEntry{{inode: 1, pid: 0}})
	updateLinuxProcNetEnrichMiss(nc, []connEntry{{inode: 2, pid: 0}})
	if v := nc.linuxEnrichMissStreak.Load(); v < 2 {
		t.Fatalf("streak=%d want >=2", v)
	}
	updateLinuxProcNetEnrichMiss(nc, []connEntry{{inode: 1, pid: 42}})
	if nc.linuxEnrichMissStreak.Load() != 0 {
		t.Fatalf("streak=%d want 0 after PID hit", nc.linuxEnrichMissStreak.Load())
	}
}
