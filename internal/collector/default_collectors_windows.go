//go:build windows

package collector

import (
	"context"
	"os"
	"path/filepath"

	"github.com/razatechofficial/edr/internal/config"
)

// extendWindowsEvtCollectors appends Sysmon Operational and PowerShell/Defender
// event-log collectors on Windows builds. Kernel ETW stays separate via
// NewKernelCollector; these sources complement it with channel-native XML rows.
func extendWindowsEvtCollectors(cols []Collector, cfg config.Config, endpointID string) []Collector {
	host, _ := os.Hostname()
	dd := cfg.Agent.DataDir
	if dd == "" {
		dd = "."
	}

	det := NewSysmonDetector(cfg.Monitoring.SysmonAutoInstall, filepath.Join("pkg", "sysmon"))
	st := det.Probe(context.Background())
	sm := NewSysmonSource(endpointID, host, dd, cfg.Monitoring.WindowsSysmonNetworkEvents)
	sm.SetChannelPresent(st.ChannelPresent)

	ps := NewPowerShellDefenderSource(endpointID, host, dd)

	cols = append(cols, sm, ps)
	if cfg.Monitoring.DnsClientETWWindows || IsRegulatedMonitoring(cfg) {
		dns := NewDnsClientEVTSource(endpointID, dd)
		// Canonical pillar name is "dns"; source-specific identity is retained
		// in source/notes within ExportMonitoringHealth.
		cols = append(cols, newStreamingRunCollector("dns", 256, cfg.Monitoring.StreamMaxEPS, dns.Run, dns.ExportMonitoringHealth))
	}
	return cols
}
