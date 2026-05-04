//go:build windows

package collector

import (
	"strings"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

func (nc *NetworkCollector) exportNetworkHealthWindows() map[string]any {
	elev := isNetWindowsElevated()
	sysmon := windowsSysmonOperationalPresent()
	poll, _ := nc.windowsShouldPollUserlandNet()
	policyDesc := WindowsUserlandNetPolicyDesc(nc.cfg)

	src := MonitoringSource{
		Name:    "network",
		OS:      "windows",
		Status:  "healthy",
		EPSIn:   nc.scans.Load(),
		EPSOut:  nc.emitted.Load(),
		Dropped: nc.dropped.Load(),
	}
	var b strings.Builder
	if poll {
		src.Source = "iphlpapi_extended_tcp"
		b.WriteString("Userland MIB snapshots (GetExtendedTcp*, non-LISTEN, PID-qualified) active; TCP-only pillar (GetExtendedUdpTable not used—product policy); rely on ETW/Sysmon for UDP-class visibility; ")
		b.WriteString("policy=")
		b.WriteString(policyDesc)
		b.WriteString("; ")
		if sysmon {
			b.WriteString("Sysmon/network EIDs may overlap—use monitoring.windows_sysmon_network_events false to reduce dupes. ")
		}
		if elev {
			b.WriteString("Elevated: kernel ETW may also emit sockets; userland path remains for dedup-aware coverage unless policy delegates.")
		}
	} else {
		src.Source = "etw_sysmon_delegate"
		b.WriteString("Userland MIB polling off (")
		b.WriteString(policyDesc)
		b.WriteString("); network pillar defers to Sysmon/kernel streams. ")
		if elev {
			b.WriteString("Elevated ETW may emit kernel network events. ")
		} else {
			b.WriteString("Process not elevated. ")
		}
		if sysmon {
			b.WriteString(" Sysmon Operational present.")
		} else if !elev {
			src.Status = "degraded"
			b.WriteString(" Sysmon channel absent.")
		} else {
			b.WriteString(" Sysmon absent; prefer kernel ETW for socket-class events.")
		}
	}
	src.Notes = strings.TrimSpace(b.String())
	return src.ToMap()
}

func isNetWindowsElevated() bool {
	var tok windows.Token
	err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_QUERY, &tok)
	if err != nil {
		return false
	}
	defer tok.Close()
	return tok.IsElevated()
}

func windowsSysmonOperationalPresent() bool {
	const path = `SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Sysmon/Operational`
	key, err := registry.OpenKey(registry.LOCAL_MACHINE, path, registry.QUERY_VALUE)
	if err != nil {
		return false
	}
	defer key.Close()
	return true
}
