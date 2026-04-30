//go:build linux

package collector

import "github.com/razatechofficial/edr/internal/config"

func extendLinuxMonitoringCollectors(cols []Collector, cfg config.Config, endpointID string, tracker *LineageTracker, addDistinctJournaldAuth bool) []Collector {
	if cfg.Monitoring.JournaldAuth && addDistinctJournaldAuth {
		j := NewJournaldSource(endpointID, "", tracker, nil)
		cols = append(cols, newStreamingRunCollector("journald_auth", 256, cfg.Monitoring.StreamMaxEPS, j.Run, j.ExportMonitoringHealth))
	}
	if mounts := cfg.Monitoring.LinuxFanotifyMounts; len(mounts) > 0 {
		f := NewFanotifySource(endpointID, "", tracker, mounts)
		cols = append(cols, newStreamingRunCollector("fanotify_file", 512, cfg.Monitoring.StreamMaxEPS, f.Run, f.ExportMonitoringHealth))
	}
	if cfg.Monitoring.LinuxAuditNetlink {
		a := NewAuditSource(endpointID, "", tracker)
		cols = append(cols, newStreamingRunCollector("linux_audit", 512, cfg.Monitoring.StreamMaxEPS, a.Run, a.ExportMonitoringHealth))
	}
	if cfg.Monitoring.LinuxUSBBridge {
		u := NewUSBCollector(endpointID, "")
		cols = append(cols, newStreamingRunCollector("usb", 64, cfg.Monitoring.StreamMaxEPS, u.Run, u.ExportMonitoringHealth))
	}
	return cols
}
