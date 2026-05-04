//go:build linux

package collector

import "context"

func applyLinuxProcNetPIDEnrichIfConfigured(ctx context.Context, nc *NetworkCollector, conns []connEntry) {
	if nc == nil || !nc.cfg.Monitoring.LinuxProcNetPIDEnrich {
		return
	}
	inodeToPID := buildSocketInodeToPIDMap(ctx, nil)
	for i := range conns {
		if conns[i].inode == 0 {
			continue
		}
		if pid, ok := inodeToPID[conns[i].inode]; ok {
			conns[i].pid = int(pid)
		}
	}
	updateLinuxProcNetEnrichMiss(nc, conns)
}

func updateLinuxProcNetEnrichMiss(nc *NetworkCollector, conns []connEntry) {
	withInode := 0
	withPID := 0
	for _, c := range conns {
		if c.inode == 0 {
			continue
		}
		withInode++
		if c.pid != 0 {
			withPID++
		}
	}
	if withInode == 0 {
		return
	}
	if withPID == 0 {
		v := nc.linuxEnrichMissStreak.Add(1)
		if v > 10000 {
			nc.linuxEnrichMissStreak.Store(10000)
		}
	} else {
		nc.linuxEnrichMissStreak.Store(0)
	}
}
