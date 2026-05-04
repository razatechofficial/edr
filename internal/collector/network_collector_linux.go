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
	updateLinuxProcNetEnrichStats(nc, conns)
}

func updateLinuxProcNetEnrichStats(nc *NetworkCollector, conns []connEntry) {
	if nc == nil || !nc.cfg.Monitoring.LinuxProcNetPIDEnrich {
		return
	}
	var withInode, withPID uint64
	for _, c := range conns {
		if c.inode == 0 {
			continue
		}
		withInode++
		if c.pid != 0 {
			withPID++
		}
	}
	nc.linuxEnrichInodeLast.Store(withInode)
	nc.linuxEnrichPIDLast.Store(withPID)

	if withInode < 5 {
		nc.linuxEnrichLowRateStreak.Store(0)
		return
	}
	rate := float64(withPID) / float64(withInode)
	if rate < 0.05 {
		v := nc.linuxEnrichLowRateStreak.Add(1)
		if v > 10000 {
			nc.linuxEnrichLowRateStreak.Store(10000)
		}
	} else {
		nc.linuxEnrichLowRateStreak.Store(0)
	}
}
