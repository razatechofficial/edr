//go:build darwin && cgo && !nosec

package kernel

// macOS capability report: which event categories the Endpoint Security
// Framework driver is actually serving.
//
// The attach evidence here is coarser than on Linux and the report says so.
// es_subscribe is called once with the whole event list (esf_subscribe_all in
// driver_darwin.go) and returns a single success or failure for all of them, so
// there is no per-event-type attach result to read. Start() returns an error
// and leaves running false when that call fails, which makes "running" the
// only subscription evidence available. Categories are therefore reported with
// DerivationRuntimeProvider, not DerivationRuntimeAttach.
//
// A second honesty problem is specific to this platform: a good part of
// esf_subscribe_all's event list is wrapped in #ifdef guards, because those
// event types only exist in newer macOS SDKs. Go cannot see which ones
// survived preprocessing. Those categories carry a reason that says their
// presence is conditional on the build SDK and is not proof the event type
// compiled in. The one unambiguous signal for them is Producing, which comes
// from events that actually arrived.

// ESF event-name constants used as attachment names in the report. These are
// the Apple event type names, which is what a macOS engineer will search for.
const (
	esfAuthExec     = "ES_EVENT_TYPE_AUTH_EXEC"
	esfNotifyExec   = "ES_EVENT_TYPE_NOTIFY_EXEC"
	esfNotifyFork   = "ES_EVENT_TYPE_NOTIFY_FORK"
	esfNotifyExit   = "ES_EVENT_TYPE_NOTIFY_EXIT"
	esfAuthOpen     = "ES_EVENT_TYPE_AUTH_OPEN"
	esfAuthCreate   = "ES_EVENT_TYPE_AUTH_CREATE"
	esfNotifyWrite  = "ES_EVENT_TYPE_NOTIFY_WRITE"
	esfNotifyTrunc  = "ES_EVENT_TYPE_NOTIFY_TRUNCATE"
	esfNotifyExch   = "ES_EVENT_TYPE_NOTIFY_EXCHANGEDATA"
	esfNotifyFcntl  = "ES_EVENT_TYPE_NOTIFY_FCNTL"
	esfAuthUnlink   = "ES_EVENT_TYPE_AUTH_UNLINK"
	esfNotifyUnlink = "ES_EVENT_TYPE_NOTIFY_UNLINK"
	esfAuthRename   = "ES_EVENT_TYPE_AUTH_RENAME"
	esfNotifyRename = "ES_EVENT_TYPE_NOTIFY_RENAME"
	esfAuthCopyfile = "ES_EVENT_TYPE_AUTH_COPYFILE"
	esfAuthMmap     = "ES_EVENT_TYPE_AUTH_MMAP"
	esfNotifyMmap   = "ES_EVENT_TYPE_NOTIFY_MMAP"
	esfAuthKextload = "ES_EVENT_TYPE_AUTH_KEXTLOAD"
	esfAuthMount    = "ES_EVENT_TYPE_AUTH_MOUNT"
	esfAuthSignal   = "ES_EVENT_TYPE_AUTH_SIGNAL"
	esfNotifySignal = "ES_EVENT_TYPE_NOTIFY_SIGNAL"
	esfAuthGetTask  = "ES_EVENT_TYPE_AUTH_GET_TASK"
	esfNotifyMprot  = "ES_EVENT_TYPE_NOTIFY_MPROTECT"
	esfNotifyRemote = "ES_EVENT_TYPE_NOTIFY_REMOTE_THREAD_CREATE"
	esfNotifySetuid = "ES_EVENT_TYPE_NOTIFY_SETUID"
	esfNotifySetgid = "ES_EVENT_TYPE_NOTIFY_SETGID"
)

// esfSDKConditional is the reason attached to categories whose only ESF event
// types are #ifdef-guarded in esf_subscribe_all.
const esfSDKConditional = "this category's ESF event types are #ifdef-guarded in esf_subscribe_all, so whether they compiled in depends on the macOS SDK the agent was built against; Go cannot read that, and only a non-zero events_observed proves the subscription is live"

// esfHookCategories maps ESF event types to the categories they serve.
//
// Categories with no entry are absent on macOS by design and are reported
// present=false: ESF has no registry, no scheduler telemetry, no TLS
// inspection, no DNS event (DNS on macOS comes from a userspace log-stream
// collector, not from this driver), no module-unload event, no inbound-accept
// event, and no connection-close event.
//
// It has no outbound-connect or bind event either, which this table used to
// claim. esfNotifyConnect and esfNotifyBind named
// ES_EVENT_TYPE_NOTIFY_CONNECT and ES_EVENT_TYPE_NOTIFY_BIND; neither
// identifier exists in the EndpointSecurity enum -- the only connect- and
// bind-shaped events Apple defines are UIPC (unix-domain socket) and
// XPC_CONNECT. esf_subscribe_all guards both with #ifdef, so they compiled to
// nothing under every SDK, and the report advertised network_connect and
// network_bind as present on every macOS agent while no event could ever
// arrive for them. Socket-level network telemetry on macOS comes from the
// NetworkExtension provider (internal/kernel/networkext), not from ESF.
var esfHookCategories = map[string][]CapabilityCategory{
	esfAuthExec:   {CapProcessExec},
	esfNotifyExec: {CapProcessExec},
	esfNotifyFork: {CapProcessFork},
	esfNotifyExit: {CapProcessExit},

	esfAuthOpen:     {CapFileOpen},
	esfAuthCreate:   {CapFileOpen},
	esfNotifyWrite:  {CapFileWrite},
	esfNotifyTrunc:  {CapFileWrite},
	esfNotifyExch:   {CapFileWrite},
	esfNotifyFcntl:  {CapFileWrite},
	esfAuthCopyfile: {CapFileWrite},
	esfAuthUnlink:   {CapFileDelete},
	esfNotifyUnlink: {CapFileDelete},
	esfAuthRename:   {CapFileRename},
	esfNotifyRename: {CapFileRename},

	esfAuthMmap:     {CapModuleLoad},
	esfNotifyMmap:   {CapModuleLoad},
	esfAuthKextload: {CapModuleLoad},

	esfAuthMount:    {CapMount},
	esfAuthSignal:   {CapSignal},
	esfNotifySignal: {CapSignal},
	esfAuthGetTask:  {CapPtrace},
	esfNotifyMprot:  {CapMemoryWrite},
	esfNotifyRemote: {CapMemoryWrite},

	// SDK-conditional below.
	esfNotifySetuid: {CapCredentialChange},
	esfNotifySetgid: {CapCredentialChange},
}

var esfConditionalHooks = map[string]string{
	esfNotifySetuid: esfSDKConditional,
	esfNotifySetgid: esfSDKConditional,
}

// CapabilityReport reports what the ESF driver has subscribed and what it has
// actually seen. It implements CapabilityReporter.
func (d *ESFDriver) CapabilityReport() CapabilityReport {
	if d == nil {
		return emptyCapabilityReport("esf", "no ESF driver instance")
	}

	running := d.running.Load()
	mechanisms := capabilityMechanismsFor("esf_subscription", esfHookCategories, esfConditionalHooks)

	// es_subscribe is all-or-nothing and Start() leaves running false when
	// it fails, so a running driver has every event type in the table
	// subscribed. Deriving the set this way rather than hardcoding "all
	// attached" keeps it tied to the one fact actually known at runtime.
	attached := make(map[string]bool, len(esfHookCategories))
	if running {
		for name := range esfHookCategories {
			attached[name] = true
		}
	}

	return buildCapabilityReport(
		"esf",
		running,
		d.Stats().UptimeSeconds,
		mechanisms,
		attached,
		DerivationRuntimeProvider,
		d.caps,
		"the Endpoint Security Framework exposes no event for this category on macOS",
	)
}
