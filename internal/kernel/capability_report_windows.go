//go:build windows

package kernel

// Windows capability report: which event categories the ETW driver is
// actually serving.
//
// Attach evidence here is per provider and genuinely runtime: startSessions
// calls recordProviderHealth for every provider it tries, with the enable
// error when the enable failed, and ProviderHealthSnapshot replays that. A
// provider the host denied, or one that needs a privilege the service does not
// hold, is recorded inactive and the categories behind it are reported
// unattached with the provider's own error as the reason. That is the most
// useful thing this report can tell a Windows operator, because an ETW
// provider failing to enable is the normal Windows failure mode and it is
// otherwise invisible.
//
// Granularity is the honest caveat, and it is why these rows carry
// DerivationRuntimeProvider rather than DerivationRuntimeAttach: one provider
// serves several categories, so process_exec and process_exit share a single
// attach fact. Producing is still per category, because handleEventRecord
// knows the ETW event ID and can tell a ProcessStart from a ProcessStop.

// ETW provider names, matching the name strings in etwCoreProviders and
// providersToStart in driver_windows.go. These are the attachment names in the
// report and the keys ProviderHealthSnapshot returns.
const (
	etwProviderProcess  = "Process"
	etwProviderFile     = "File"
	etwProviderNetwork  = "Network"
	etwProviderDNS      = "DNS"
	etwProviderRegistry = "Registry"
)

// etwHookCategories maps ETW provider names to the categories they serve.
//
// Categories with no entry have no ETW provider in the core set: the Windows
// kernel providers used here expose no credential-change, namespace, mount,
// scheduler or TLS-metadata telemetry that this driver subscribes to, and
// kernel module load/unload is not among the enabled providers either.
var etwHookCategories = map[string][]CapabilityCategory{
	etwProviderProcess: {CapProcessExec, CapProcessExit},
	etwProviderFile:    {CapFileOpen, CapFileWrite, CapFileDelete, CapFileRename},
	etwProviderNetwork: {CapNetworkConnect, CapNetworkAccept, CapNetworkClose},
	etwProviderDNS:     {CapNetworkDNS},
	// Registry is the one category that exists only on Windows.
	etwProviderRegistry: {CapRegistryWrite},
}

// file_permission is deliberately absent even though Kernel-File does emit
// security-descriptor events. On windows-latest an icacls grant/remove pair
// produces exactly one event id 31 and one id 34 per operation, and from the
// event ids alone there is no way to tell the set from the query — crediting a
// security-descriptor *read* to file_permission would be a wrong row, which
// this report treats as worse than a blank one. Telling them apart needs
// TdhGetEventInformation to resolve the template by name, which this driver
// does not do yet.

// etwCoarseProviders notes where one provider backs several categories, so the
// report can say that attach state is shared rather than per category.
const etwCoarseProvider = "attach state for this category is per ETW provider, not per event: the provider serves several categories at once, so events_observed is the only per-category evidence"

var etwCoarseHooks = map[string]string{
	etwProviderProcess: etwCoarseProvider,
	etwProviderFile:    etwCoarseProvider,
	etwProviderNetwork: etwCoarseProvider,
}

// attachedETWProviders returns the set of provider names that enabled
// successfully, from the health records the driver wrote at start.
func (d *ETWDriver) attachedETWProviders() map[string]bool {
	out := make(map[string]bool)
	if d == nil {
		return out
	}
	for _, h := range d.ProviderHealthSnapshot() {
		if h.Active {
			out[h.Name] = true
		}
	}
	return out
}

// etwProviderErrors returns the recorded enable error per inactive provider,
// so an unattached category can report the real cause instead of a generic
// message.
func (d *ETWDriver) etwProviderErrors() map[string]string {
	out := make(map[string]string)
	if d == nil {
		return out
	}
	for _, h := range d.ProviderHealthSnapshot() {
		if !h.Active && h.Error != "" {
			out[h.Name] = h.Error
		}
	}
	return out
}

// CapabilityReport reports which ETW providers enabled and what they have
// produced. It implements CapabilityReporter.
func (d *ETWDriver) CapabilityReport() CapabilityReport {
	if d == nil {
		return emptyCapabilityReport("etw", "no ETW driver instance")
	}

	running := d.running.Load()
	attached := d.attachedETWProviders()

	// Prefer the provider's own enable error over the generic coarseness
	// note: when a provider failed, why it failed is the thing an operator
	// needs, and the coarseness caveat only matters once it is working.
	reasons := make(map[string]string, len(etwCoarseHooks))
	for k, v := range etwCoarseHooks {
		reasons[k] = v
	}
	for name, errText := range d.etwProviderErrors() {
		reasons[name] = "ETW provider " + name + " failed to enable: " + errText
	}

	mechanisms := capabilityMechanismsFor("etw_provider", etwHookCategories, reasons)

	notBuilt := "no ETW provider in this driver's provider set serves this category"
	if running && len(attached) == 0 {
		notBuilt = "ETW driver is running but no provider enabled successfully; check that the service holds SeSystemProfilePrivilege and that the trace session could start"
	}

	return buildCapabilityReport(
		"etw",
		running,
		d.Stats().UptimeSeconds,
		mechanisms,
		attached,
		DerivationRuntimeProvider,
		d.caps,
		notBuilt,
	)
}

// windowsCapabilityForETWEvent maps an ETW provider and event ID to the
// capability category the tracker should credit.
//
// The event ids are the ones a hosted windows-latest runner actually delivers,
// measured by generating a labelled burst of one kind of activity at a time
// and reading off which id moved. That matters, because the table this
// replaced was written from the NT Kernel Logger MOF opcode numbering
// (FileIo opcode 67 read / 68 write, TcpIp opcode 17 connect / 16 accept)
// while the driver enables the Microsoft-Windows-Kernel-* manifest providers,
// which number the same operations differently. The consequence was not a
// subtle one: file_write, file_delete, network_connect and network_accept
// could never be credited at all, and Kernel-Network's Accept (id/opcode 15)
// was credited to network_close, which is the wrong-row case the comment
// below says is worse than a blank one.
//
// opcode is still accepted so the signature does not change for callers;
// Kernel-Network sets it equal to the event id and the other providers leave
// it at a value that carries no routing information.
//
// An unrecognised ID returns an empty category and is credited to nothing: a
// provider is reported attached-but-not-producing rather than having an event
// counted against the wrong row.
func windowsCapabilityForETWEvent(provider string, eventID uint16, opcode uint8) CapabilityCategory {
	_ = opcode
	switch provider {
	case etwProviderProcess:
		// Kernel-Process: 1 ProcessStart, 2 ProcessStop
		// (decodeProcessUserData switches on exactly these).
		switch eventID {
		case 1:
			return CapProcessExec
		case 2:
			return CapProcessExit
		}
	case etwProviderFile:
		switch eventID {
		case kernelFileEvtCreateID, kernelFileEvtCreateNewID:
			return CapFileOpen
		case kernelFileEvtWriteID:
			return CapFileWrite
		case kernelFileEvtSetDeleteID, kernelFileEvtDeletePathID:
			return CapFileDelete
		case kernelFileEvtRenameID, kernelFileEvtRenamePathID:
			return CapFileRename
		}
	case etwProviderNetwork:
		// Kernel-Network numbers its TCP templates in blocks of 16:
		// IPv4 at 10, IPv6 at 26, with the same order in each
		// (datasent, datareceived, connectionattempted,
		// disconnectissued, retransmit, accept, reconnect, copy), and
		// UDP IPv4 at 42. Opcode carries the same number as the event
		// id on this provider, so only the id is consulted.
		switch eventID {
		case kernelNetEvtConnect4, kernelNetEvtConnect6:
			return CapNetworkConnect
		case kernelNetEvtAccept4, kernelNetEvtAccept6:
			return CapNetworkAccept
		case kernelNetEvtDisconnect4, kernelNetEvtDisconnect6:
			return CapNetworkClose
		}
	case etwProviderDNS:
		return CapNetworkDNS
	case etwProviderRegistry:
		return CapRegistryWrite
	}
	return ""
}
