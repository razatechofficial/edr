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
	if cfg.Monitoring.WindowsAmsiTamperEnabled || cfg.Monitoring.WindowsEtwTamperEnabled {
		am := NewAmsiEtwTamperSource(endpointID, host, cfg)
		cols = append(cols, newStreamingRunCollector("amsi_etw_tamper", 32, cfg.Monitoring.StreamMaxEPS, am.Run, am.ExportMonitoringHealth))
	}
	if cfg.Monitoring.WindowsADSEnumerator {
		ad := NewADSEnumeratorSource(endpointID, host, cfg)
		cols = append(cols, newStreamingRunCollector("ads_enumerator", 64, cfg.Monitoring.StreamMaxEPS, ad.Run, ad.ExportMonitoringHealth))
	}
	if cfg.Monitoring.WindowsAutorunsLite {
		ar := NewAutorunsLiteSource(endpointID, host, cfg)
		cols = append(cols, newStreamingRunCollector("autoruns_lite", 128, cfg.Monitoring.StreamMaxEPS, ar.Run, ar.ExportMonitoringHealth))
	}
	if cfg.Monitoring.WindowsCOMHijackHunt {
		ch := NewCOMHijackWatchSource(endpointID, cfg)
		cols = append(cols, newStreamingRunCollector("com_hijack", 64, cfg.Monitoring.StreamMaxEPS, ch.Run, ch.ExportMonitoringHealth))
	}
	if cfg.Monitoring.WindowsDLLSearchPosture {
		ds := NewDLLSearchPostureSource(endpointID, cfg)
		cols = append(cols, newStreamingRunCollector("dll_search_posture", 32, cfg.Monitoring.StreamMaxEPS, ds.Run, ds.ExportMonitoringHealth))
	}
	if cfg.Monitoring.WindowsWMIPersistenceHunt {
		w := NewWMIPersistenceWatchSource(endpointID, cfg)
		cols = append(cols, newStreamingRunCollector("wmi_persistence", 96, cfg.Monitoring.StreamMaxEPS, w.Run, w.ExportMonitoringHealth))
	}
	return cols
}
