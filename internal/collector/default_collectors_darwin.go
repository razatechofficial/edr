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
	return cols
}
