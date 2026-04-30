//go:build linux

package collector

import "github.com/razatechofficial/edr/internal/config"

func extendLinuxMonitoringCollectors(cols []Collector, cfg config.Config, endpointID string, tracker *LineageTracker) []Collector {
	if cfg.Monitoring.JournaldAuth {
		j := NewJournaldSource(endpointID, "", tracker, nil)
		cols = append(cols, newStreamingRunCollector("journald_auth", 256, j.Run, j.ExportMonitoringHealth))
	}
	if mounts := cfg.Monitoring.LinuxFanotifyMounts; len(mounts) > 0 {
		f := NewFanotifySource(endpointID, "", tracker, mounts)
		cols = append(cols, newStreamingRunCollector("fanotify_file", 512, f.Run, f.ExportMonitoringHealth))
	}
	if cfg.Monitoring.LinuxAuditNetlink {
		a := NewAuditSource(endpointID, "", tracker)
		cols = append(cols, newStreamingRunCollector("linux_audit", 512, a.Run, a.ExportMonitoringHealth))
	}
	if cfg.Monitoring.LinuxUSBBridge {
		u := NewUSBCollector(endpointID, "")
		cols = append(cols, newStreamingRunCollector("usb", 64, u.Run, u.ExportMonitoringHealth))
	}
	return cols
}
