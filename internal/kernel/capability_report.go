package kernel

// Monitoring capability self-report.
//
// This answers one operational question the agent could not previously answer
// about itself: "is this agent actually monitoring?" The existing surfaces do
// not. Driver.Capabilities() returns a hardcoded list of event types the
// driver's author intended to support, which stays true after the mechanism
// behind it has stopped working. DriverStats gives totals with no breakdown,
// so a driver that attached forty programs and lost its network ones still
// reports a healthy event rate from the other thirty-nine.
//
// A capability report instead separates three facts per event category, which
// fail independently and have different fixes:
//
//	present   — a mechanism for this category exists in this build on this OS.
//	            False means the code is not there: wrong GOOS, CGO disabled,
//	            nosec build, program not compiled into the object.
//	attached  — the mechanism is hooked into the kernel right now. Built from
//	            what the driver recorded at attach time, never from a static
//	            list. False with present true is the interesting case: the
//	            code shipped and the hook did not take.
//	producing — at least one event in this category has actually arrived.
//	            False with attached true means the hook is live but silent,
//	            which is either a quiet host or a broken decode path.
//
// Those three are deliberately not collapsed into one status. "Attached but
// not producing" on a freshly started agent is normal; the same state after an
// hour of load is a defect, and only the console has the context to tell them
// apart. It gets the three booleans and decides.
//
// Each category also carries Derivation, which states what evidence backs
// Attached. A report that cannot determine real attach state says so there
// rather than guessing, because a capability report that overstates itself is
// worse than none.

import (
	"runtime"
	"sort"
	"sync/atomic"
	"time"
)

// CapabilityReportSchemaVersion increments when the JSON shape or the meaning
// of a field changes materially. The console keys off it.
//
// v1: initial shape — schema_version, generated_at, os, arch, driver,
// driver_running, uptime_seconds, categories[], summary{}.
// v2: adds categories[].live, categories[].live_evidence and summary.live.
// Additive — every v1 key keeps its meaning, so a v1 consumer still parses a
// v2 report. The version moves anyway because a consumer has to be able to
// tell "this agent reports liveness and the hook is not confirmed" from "this
// agent predates the field", and those look identical if live is just absent.
const CapabilityReportSchemaVersion = 2

// CapabilityCategory names one class of monitored activity.
//
// These are the report's stable vocabulary: the console renders them and
// operators read them, so values are never renamed, only added. They are
// deliberately finer than pkg/events.EventType — "file" as a single row cannot
// express that opens are seen and deletes are not, which is exactly the
// distinction that matters when deciding whether a detection rule can fire.
type CapabilityCategory string

// Canonical categories. Not every OS can serve every one; a category with no
// mechanism on this OS is reported present=false with a reason rather than
// omitted, so the console shows a complete, comparable matrix across a fleet
// of mixed platforms.
const (
	CapProcessExec = CapabilityCategory("process_exec")
	CapProcessExit = CapabilityCategory("process_exit")
	CapProcessFork = CapabilityCategory("process_fork")

	CapFileOpen       = CapabilityCategory("file_open")
	CapFileWrite      = CapabilityCategory("file_write")
	CapFileDelete     = CapabilityCategory("file_delete")
	CapFileRename     = CapabilityCategory("file_rename")
	CapFilePermission = CapabilityCategory("file_permission")

	CapNetworkConnect = CapabilityCategory("network_connect")
	CapNetworkAccept  = CapabilityCategory("network_accept")
	CapNetworkBind    = CapabilityCategory("network_bind")
	CapNetworkClose   = CapabilityCategory("network_close")
	CapNetworkDNS     = CapabilityCategory("network_dns")

	CapModuleLoad   = CapabilityCategory("module_load")
	CapModuleUnload = CapabilityCategory("module_unload")

	CapCredentialChange = CapabilityCategory("credential_change")
	CapNamespaceChange  = CapabilityCategory("namespace_change")

	CapPtrace      = CapabilityCategory("ptrace")
	CapSignal      = CapabilityCategory("signal")
	CapMemoryWrite = CapabilityCategory("memory_write")
	CapMount       = CapabilityCategory("mount")

	CapRegistryWrite = CapabilityCategory("registry_write")

	CapScheduler   = CapabilityCategory("scheduler")
	CapTLSMetadata = CapabilityCategory("tls_metadata")
)

// CanonicalCapabilityCategories is the full ordered category list.
//
// Order is presentation order for the console and is stable across releases;
// new categories append. Every report covers exactly this set, so two agents
// on different platforms produce comparable rows.
var CanonicalCapabilityCategories = []CapabilityCategory{
	CapProcessExec, CapProcessExit, CapProcessFork,
	CapFileOpen, CapFileWrite, CapFileDelete, CapFileRename, CapFilePermission,
	CapNetworkConnect, CapNetworkAccept, CapNetworkBind, CapNetworkClose, CapNetworkDNS,
	CapModuleLoad, CapModuleUnload,
	CapCredentialChange, CapNamespaceChange,
	CapPtrace, CapSignal, CapMemoryWrite, CapMount,
	CapRegistryWrite,
	CapScheduler, CapTLSMetadata,
}

// Derivation values state what evidence backs a category's Attached flag.
// The console should treat anything other than a runtime derivation as a
// weaker claim.
const (
	// DerivationRuntimeAttach: the driver recorded a successful attach call
	// for a named hook and the report read that record. Strongest claim.
	DerivationRuntimeAttach = "runtime_attach"

	// DerivationRuntimeProvider: the driver recorded a per-provider or
	// per-subscription enable result at start (Windows ETW providers,
	// macOS ESF subscription). Real runtime evidence, but coarser than a
	// per-hook attach: one provider covers several categories.
	DerivationRuntimeProvider = "runtime_provider"

	// DerivationNotBuilt: no mechanism for this category exists in this
	// build on this OS. Attached is false and Reason says why.
	DerivationNotBuilt = "not_built"

	// DerivationDriverStopped: the driver is not running, so nothing is
	// attached regardless of what the build contains.
	DerivationDriverStopped = "driver_stopped"
)

// CapabilityStatus is one row of the report: the state of one event category.
// Evidence that a category's hooks are doing work, strongest first. An event
// reaching userspace proves the whole path; a kernel submission proves the
// hook fired and leaves the loss downstream; an invocation count proves only
// that the kernel entered the program, which is still the difference between
// "armed" and "not yet armed".
// reasonAttachedNotConfirmed is written on an attached row with no liveness
// evidence yet. Held as a constant so the later passes can recognise and
// retract exactly this note without touching a more specific one.
const reasonAttachedNotConfirmed = "the attach call succeeded; no hook for this category has been observed to run yet, so it is not confirmed working"

const (
	LiveEvidenceEvent           = "event_observed"
	LiveEvidenceKernelSubmitted = "kernel_submitted"
	LiveEvidenceProgramInvoked  = "program_invoked"
)

type CapabilityStatus struct {
	Category CapabilityCategory `json:"category"`

	// Present: a mechanism for this category exists in this build on this
	// OS. Says nothing about whether it is hooked up.
	Present bool `json:"present"`

	// Attached: the attach call for this category's hooks returned
	// success, per Derivation. Always false when Present is false.
	//
	// This is weaker than it reads, which is why Live exists. On some
	// kernels a hook arms a short time after the attach call returns: the
	// link is recorded, the programs are loaded, and the kernel does not
	// invoke them for syscalls made in the meantime. Measured on GitHub's
	// 7.0.0-1017-azure image, where a program the kernel had invoked zero
	// times sat alongside a sibling in the same object invoked 5863 times,
	// and every category eventually came alive. Attached answers "did the
	// attach succeed"; it does not answer "is this hook doing work".
	Attached bool `json:"attached"`

	// Live: this category's hooks have been observed to do work, per
	// LiveEvidence. Always false when Attached is false.
	//
	// This is the field to show an operator. Attached-but-not-Live is the
	// arming window above, or a hook that is genuinely never invoked;
	// either way the honest reading is "not confirmed working yet", not
	// "working, and the host is quiet". The distinction matters most for a
	// short-lived agent — a container, a diagnostic run, a crash-restart
	// loop — which could otherwise report itself healthy for the whole of
	// its life while seeing nothing.
	Live bool `json:"live"`

	// LiveEvidence names what established Live, so the claim can be
	// audited rather than trusted. Empty when Live is false.
	LiveEvidence string `json:"live_evidence,omitempty"`

	// Producing: at least one event of this category has been observed
	// since the driver started. Always false when Attached is false.
	Producing bool `json:"producing"`

	// Mechanism is the kind of hook, e.g. "ebpf_tracepoint", "ebpf_lsm",
	// "etw_provider", "esf_subscription". Empty when Present is false.
	Mechanism string `json:"mechanism,omitempty"`

	// Attachments names the concrete hooks backing this category: eBPF
	// program names, ETW provider names, ESF event names. This is what an
	// engineer needs to go look at something; the console can hide it.
	Attachments []string `json:"attachments,omitempty"`

	// EventsObserved counts events attributed to this category since the
	// driver started. Monotonic for the life of the driver.
	EventsObserved uint64 `json:"events_observed"`

	// LastEventUnix is the unix second of the most recent event in this
	// category, or 0 if none. The console uses the gap between this and
	// GeneratedAt to decide whether "attached but not producing" is stale.
	LastEventUnix int64 `json:"last_event_unix"`

	// KernelDropped counts events of this category the kernel produced and
	// then threw away because the ring buffer carrying them was full.
	// Linux eBPF only; zero elsewhere.
	//
	// It is the answer to the most misleading row this report can show:
	// attached true, producing false, events_observed zero. That row used
	// to mean "the hook is not firing" and nothing else, because a record
	// lost in the kernel left no trace in userspace. A non-zero value here
	// says the hook is firing fine and the agent cannot keep up.
	KernelDropped uint64 `json:"kernel_dropped,omitempty"`

	// KernelSubmitted counts events of this category the kernel wrote into
	// a ring buffer. Read against EventsObserved it separates a loss in
	// the kernel from a loss in the userspace decode or policy gate.
	KernelSubmitted uint64 `json:"kernel_submitted,omitempty"`

	// Derivation states what evidence backs Attached. One of the
	// Derivation* constants.
	Derivation string `json:"derivation"`

	// Reason explains a false Present or Attached in operator terms. Empty
	// when the category is attached and healthy.
	Reason string `json:"reason,omitempty"`
}

// CapabilitySummary is the at-a-glance count the console shows before anyone
// expands the category table.
type CapabilitySummary struct {
	Categories int `json:"categories"`
	Present    int `json:"present"`
	Attached   int `json:"attached"`
	// Live is the count an operator should read: hooks confirmed to be
	// doing work, as opposed to hooks whose attach call returned success.
	Live      int `json:"live"`
	Producing int `json:"producing"`
}

// CapabilityReport is the whole self-report, and the stable JSON contract the
// console consumes.
//
// Field semantics:
//
//	schema_version  CapabilityReportSchemaVersion at time of generation.
//	generated_at    RFC3339Nano UTC. Compare against a category's
//	                last_event_unix to judge staleness.
//	os, arch        runtime.GOOS / runtime.GOARCH of the agent.
//	driver          Driver.Name(): "ebpf", "etw", "esf", or "none".
//	driver_running  whether the driver is started. False makes every
//	                category attached=false with derivation=driver_stopped.
//	uptime_seconds  driver uptime; 0 when not running. A low value explains
//	                attached-but-not-producing without it being a defect.
//	categories      one CapabilityStatus per CanonicalCapabilityCategories
//	                entry, in that order. Never partial.
//	summary         counts over categories.
type CapabilityReport struct {
	SchemaVersion int                `json:"schema_version"`
	GeneratedAt   string             `json:"generated_at"`
	OS            string             `json:"os"`
	Arch          string             `json:"arch"`
	Driver        string             `json:"driver"`
	DriverRunning bool               `json:"driver_running"`
	UptimeSeconds float64            `json:"uptime_seconds"`
	Categories    []CapabilityStatus `json:"categories"`
	Summary       CapabilitySummary  `json:"summary"`
}

// CapabilityReporter is implemented by drivers that can report what they
// actually attached. Callers should type-assert: a driver that cannot report
// is not a failure, it is an older or stub implementation.
type CapabilityReporter interface {
	CapabilityReport() CapabilityReport
}

// capabilityObservation is the per-category counter pair.
type capabilityObservation struct {
	count     atomic.Uint64
	lastEvent atomic.Int64
}

// capabilityTracker records, per category, that an event of that category
// arrived. Drivers call observe from their single event chokepoint.
//
// The map is fixed at construction over CanonicalCapabilityCategories and
// never written to afterwards, so observe needs no lock and no allocation: it
// is two atomic stores on the hot path of every kernel event. A sync.Map or a
// locked map would show up in a 50k-events-per-second ring buffer drain.
type capabilityTracker struct {
	obs map[CapabilityCategory]*capabilityObservation

	// now is swappable so tests can assert on last_event_unix without
	// sleeping.
	now func() time.Time
}

func newCapabilityTracker() *capabilityTracker {
	t := &capabilityTracker{
		obs: make(map[CapabilityCategory]*capabilityObservation, len(CanonicalCapabilityCategories)),
		now: time.Now,
	}
	for _, c := range CanonicalCapabilityCategories {
		t.obs[c] = &capabilityObservation{}
	}
	return t
}

// observe records one event in cat. An empty or unknown category is ignored:
// a decode path that cannot classify an event must not panic the event loop,
// and the report would rather under-claim than invent a category.
func (t *capabilityTracker) observe(cat CapabilityCategory) {
	if t == nil || cat == "" {
		return
	}
	o, ok := t.obs[cat]
	if !ok {
		return
	}
	o.count.Add(1)
	o.lastEvent.Store(t.now().Unix())
}

// snapshot reads the counters for cat.
func (t *capabilityTracker) snapshot(cat CapabilityCategory) (count uint64, lastUnix int64) {
	if t == nil {
		return 0, 0
	}
	o, ok := t.obs[cat]
	if !ok {
		return 0, 0
	}
	return o.count.Load(), o.lastEvent.Load()
}

// capabilityMechanism describes the hooks backing one category on one OS.
type capabilityMechanism struct {
	// Mechanism is the hook kind, e.g. "ebpf_tracepoint".
	Mechanism string

	// Attachments are the concrete hook names that would serve this
	// category if attached.
	Attachments []string

	// Reason, when non-empty, explains why this category cannot work even
	// though a mechanism exists — an unattached program, a missing
	// entitlement. It is carried through to the report so the known gaps
	// are visible to operators rather than only to whoever reads the
	// consistency test allowlists.
	Reason string
}

// buildCapabilityReport assembles a report from a per-OS mechanism table and
// the set of hook names the driver actually attached.
//
// mechanisms maps a category to the hooks that could serve it in this build;
// a category absent from the map is reported present=false. attachedHooks is
// the set of hook names the driver recorded at attach time — the runtime
// evidence. A category is attached when at least one of its hooks is in that
// set, which is the honest reading: the point of this report is that a program
// existing and a program being attached are different facts.
func buildCapabilityReport(
	driverName string,
	running bool,
	uptimeSeconds float64,
	mechanisms map[CapabilityCategory]capabilityMechanism,
	attachedHooks map[string]bool,
	derivation string,
	tracker *capabilityTracker,
	notBuiltReason string,
) CapabilityReport {
	rep := CapabilityReport{
		SchemaVersion: CapabilityReportSchemaVersion,
		GeneratedAt:   time.Now().UTC().Format(time.RFC3339Nano),
		OS:            runtime.GOOS,
		Arch:          runtime.GOARCH,
		Driver:        driverName,
		DriverRunning: running,
		UptimeSeconds: uptimeSeconds,
		Categories:    make([]CapabilityStatus, 0, len(CanonicalCapabilityCategories)),
	}

	for _, cat := range CanonicalCapabilityCategories {
		st := CapabilityStatus{Category: cat}

		m, present := mechanisms[cat]
		if !present {
			st.Derivation = DerivationNotBuilt
			st.Reason = notBuiltReason
			rep.Categories = append(rep.Categories, st)
			continue
		}

		st.Present = true
		st.Mechanism = m.Mechanism
		st.Attachments = append([]string(nil), m.Attachments...)
		sort.Strings(st.Attachments)

		if !running {
			st.Derivation = DerivationDriverStopped
			st.Reason = "driver is not running; nothing is attached"
			rep.Categories = append(rep.Categories, st)
			continue
		}

		st.Derivation = derivation
		var live []string
		for _, h := range st.Attachments {
			if attachedHooks[h] {
				live = append(live, h)
			}
		}
		st.Attached = len(live) > 0

		switch {
		case !st.Attached:
			// The mechanism shipped and no hook took. Prefer the
			// table's reason, which knows *why* (unattached by
			// design, prefix mismatch, missing entitlement) over a
			// generic message.
			st.Reason = m.Reason
			if st.Reason == "" {
				st.Reason = "mechanism present in this build but no hook is attached"
			}
		default:
			// Report only the hooks that are actually attached, not
			// every hook that could have been. A category listing a
			// hook it does not have would misdirect whoever reads it.
			st.Attachments = live
			if m.Reason != "" {
				// Partially attached: some hooks took, some did
				// not, and the table explains the gap.
				st.Reason = m.Reason
			}
		}

		count, last := tracker.snapshot(cat)
		st.EventsObserved = count
		st.LastEventUnix = last
		st.Producing = st.Attached && count > 0
		if st.Producing {
			st.Live = true
			st.LiveEvidence = LiveEvidenceEvent
		} else if st.Attached && st.Reason == "" {
			// Said here rather than left for the reader to infer from
			// three booleans. A partial-attach reason from the table is
			// more specific, so it is not overwritten.
			st.Reason = reasonAttachedNotConfirmed
		}

		rep.Categories = append(rep.Categories, st)
	}

	rep.Summary = summarizeCapabilities(rep.Categories)
	return rep
}

func summarizeCapabilities(in []CapabilityStatus) CapabilitySummary {
	s := CapabilitySummary{Categories: len(in)}
	for _, c := range in {
		if c.Present {
			s.Present++
		}
		if c.Attached {
			s.Attached++
		}
		if c.Producing {
			s.Producing++
		}
		if c.Live {
			s.Live++
		}
	}
	return s
}

// emptyCapabilityReport builds an all-absent report for a build or OS with no
// kernel driver at all. Every category comes back present=false with reason,
// so the console gets a complete matrix instead of an empty one it has to
// guess about.
func emptyCapabilityReport(driverName, reason string) CapabilityReport {
	return buildCapabilityReport(
		driverName, false, 0,
		nil, nil,
		DerivationNotBuilt,
		nil,
		reason,
	)
}

// capabilityMechanismsFor inverts a hook-to-categories table into the
// category-to-mechanism table buildCapabilityReport wants.
//
// Per-OS tables are written hook-first (one eBPF program serves one or two
// categories) because that is the direction they are maintained in and the
// direction a consistency test can check for completeness against the parsed
// program list.
func capabilityMechanismsFor(mechanism string, hookCategories map[string][]CapabilityCategory, reasons map[string]string) map[CapabilityCategory]capabilityMechanism {
	out := make(map[CapabilityCategory]capabilityMechanism)
	hooks := make([]string, 0, len(hookCategories))
	for h := range hookCategories {
		hooks = append(hooks, h)
	}
	sort.Strings(hooks)

	for _, hook := range hooks {
		for _, cat := range hookCategories[hook] {
			m := out[cat]
			m.Mechanism = mechanism
			m.Attachments = append(m.Attachments, hook)
			if r := reasons[hook]; r != "" && m.Reason == "" {
				m.Reason = r
			}
			out[cat] = m
		}
	}
	return out
}

// clearUnconfirmedReason drops the "not confirmed working" note once something
// has established that the hooks are live.
//
// The note is written while the report is being built, before the Linux passes
// that can upgrade a row on kernel-submission or invocation evidence. Leaving
// it in place would contradict the Live field in the same row, and a row that
// argues with itself is worse than either answer alone.
func clearUnconfirmedReason(st *CapabilityStatus) {
	if st != nil && st.Reason == reasonAttachedNotConfirmed {
		st.Reason = ""
	}
}
