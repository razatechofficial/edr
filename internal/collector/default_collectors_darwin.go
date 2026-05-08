//go:build darwin

package collector

import "github.com/razatechofficial/edr/internal/config"

func extendDarwinMonitoringCollectors(cols []Collector, cfg config.Config, endpointID string, tracker *LineageTracker) []Collector {
	if cfg.Monitoring.DarwinUnifiedLogDNS {
		d := NewDarwinDNSSource(endpointID, "", tracker)
		cols = append(cols, newStreamingRunCollector("dns_unified_log", 128, cfg.Monitoring.StreamMaxEPS, d.Run, d.ExportMonitoringHealth))
	}
	if cfg.Monitoring.DarwinLogStreamDNSAlt {
		l := NewLogStreamDNSSource(endpointID, "")
		cols = append(cols, newStreamingRunCollector("dns_log_stream_alt", 128, cfg.Monitoring.StreamMaxEPS, l.Run, l.ExportMonitoringHealth))
	}
	if cfg.Monitoring.MacosTCCWatch {
		tw := NewTCCWatchSource(endpointID, "", cfg)
		cols = append(cols, newStreamingRunCollector("tcc_watch", 64, cfg.Monitoring.StreamMaxEPS, tw.Run, tw.ExportMonitoringHealth))
	}
	if cfg.Monitoring.MacosAutostartEnumerator {
		as := NewAutostartDarwinSource(endpointID, "", cfg)
		cols = append(cols, newStreamingRunCollector("autostart_darwin", 128, cfg.Monitoring.StreamMaxEPS, as.Run, as.ExportMonitoringHealth))
	}
	if cfg.Monitoring.MacosCodesignSweep {
		cs := NewCodesignSweepDarwinSource(endpointID, "", cfg)
		cols = append(cols, newStreamingRunCollector("codesign_sweep", 32, cfg.Monitoring.StreamMaxEPS, cs.Run, cs.ExportMonitoringHealth))
	}
	if cfg.Monitoring.MacosNotarizationPosture {
		np := NewMacosNotarizationPostureSource(endpointID, cfg)
		cols = append(cols, newStreamingRunCollector("macos_notarization_posture", 32, cfg.Monitoring.StreamMaxEPS, np.Run, np.ExportMonitoringHealth))
	}
	return cols
}
