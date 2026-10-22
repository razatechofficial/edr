//go:build linux

package kernel

// Kernel-side event accounting: the userspace half of event_stats and
// filter_stats in platform/linux/ebpf/common.h.
//
// Before these maps existed there was exactly one loss on the event path that
// nothing counted. bpf_ringbuf_reserve returns NULL when the ring buffer is
// full, every call site discarded the event and returned, and because the
// record never left the kernel userspace had nothing to notice: the driver's
// EventsDropped counts decode failures, RingBufferStats.Dropped counts writes
// the userspace buffer refused, and the capability report's events_observed
// counts records that arrived. All three stay at zero while the kernel throws
// events away.
//
// That is a production defect before it is a test problem. On a busy host the
// agent silently stops reporting a category and no log line, metric or health
// field says so. It also makes a failure unattributable: "no event arrived"
// reads the same whether the hook never fired, a pid filter dropped the event
// or the buffer was full, and those three have three different fixes.
//
// The two maps make them distinguishable:
//
//	event_stats[type].submitted       the hook fired and a record was written
//	event_stats[type].reserve_failed  the hook fired and the buffer was full
//	filter_stats[subsystem]           an in-kernel pid filter dropped it
//
// A type with zero of all three is a hook that did not run.

import (
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/cilium/ebpf"
)

const (
	// kernelEventStatsMap and kernelFilterStatsMap are the per-CPU array
	// maps common.h declares. Named here rather than inline so the
	// consistency model's coll.Maps["..."] scan sees them.
	kernelEventStatsMap  = "event_stats"
	kernelFilterStatsMap = "filter_stats"

	// edrEventTypeMax mirrors EDR_EVENT_TYPE_MAX in common.h: the number of
	// slots in event_stats. Changing one without the other reads the wrong
	// number of entries, so the loader asserts the map's geometry matches
	// before trusting it.
	edrEventTypeMax = 64

	// edrSubsysMax mirrors EDR_SUBSYS_MAX in common.h.
	edrSubsysMax = 8
)

// bpfEventStats mirrors struct edr_event_stats in common.h. Field order and
// width are part of the ABI with the compiled object.
type bpfEventStats struct {
	Submitted     uint64
	ReserveFailed uint64
}

// KernelEventLoss is what the kernel recorded about one event type.
type KernelEventLoss struct {
	// Type is the raw eBPF event type (the EVENT_* constant in common.h).
	Type uint32 `json:"type"`

	// Ring is the ring buffer the type's records are submitted to, which
	// is the thing to resize or drain faster when ReserveFailed is high.
	Ring string `json:"ring"`

	// Category is the capability category the type credits, so a reader
	// can line a loss up against the report row that went dark.
	Category string `json:"category,omitempty"`

	// Submitted is how many records the kernel reserved and filled.
	Submitted uint64 `json:"submitted"`

	// ReserveFailed is how many records the kernel threw away because the
	// ring buffer had no room. These never reached userspace in any form.
	ReserveFailed uint64 `json:"reserve_failed"`
}

// KernelLossReport is the whole kernel-side accounting at one instant.
type KernelLossReport struct {
	// ByType is every event type the kernel has touched, busiest loss
	// first. Types with all-zero counters are omitted: on any real host
	// most of the 64 slots are unused and listing them buries the signal.
	ByType []KernelEventLoss `json:"by_type,omitempty"`

	// ByRing totals ReserveFailed per ring buffer, which is the dimension
	// a sizing or draining fix acts on.
	ByRing map[string]uint64 `json:"by_ring,omitempty"`

	// FilterDrops totals, per subsystem, the events an in-kernel pid
	// filter dropped. The agent's own pid is always in those maps, so a
	// non-zero count here is expected and is not a fault.
	FilterDrops map[string]uint64 `json:"filter_drops,omitempty"`

	// TotalReserveFailed and TotalSubmitted are the sums over ByType.
	TotalReserveFailed uint64 `json:"total_reserve_failed"`
	TotalSubmitted     uint64 `json:"total_submitted"`

	// Available is false when the loaded object has no accounting maps,
	// which is what an object built before this existed looks like. The
	// distinction matters: zero losses and "cannot tell" are not the same
	// answer and a health surface must not report the second as the first.
	Available bool `json:"available"`

	// Reason explains a false Available.
	Reason string `json:"reason,omitempty"`
}

// edrSubsystemNames maps the subsystem ids in common.h to the .c file whose
// pid filter they count.
var edrSubsystemNames = map[uint32]string{
	0: "process",
	1: "file",
	2: "network",
	3: "security",
	4: "fim",
}

// ringForEventType names the ring buffer each event type is submitted to.
//
// This is the one place the mapping lives, and it has to track the .c files:
// the ring a type goes to is decided by which file declares the program. Kept
// as a switch rather than a map so an unmapped type is a compile-time
// omission a reader can see, and TestLinuxEventTypeRingCoverage asserts every
// bpfEvt* constant has one.
func ringForEventType(typ uint32) string {
	switch typ {
	case bpfEvtProcExec, bpfEvtProcExit, bpfEvtProcFork:
		// process_monitor.c submits to "events"; syscall_monitor.c also
		// emits fork-shaped records into sec_events from clone/vfork,
		// so a fork loss can be on either. "events" is the one whose
		// size matters for the process stream.
		return "events"
	case bpfEvtFileOpen, bpfEvtFileWrite, bpfEvtFileDel, bpfEvtFileRen,
		bpfEvtFileChmod, bpfEvtProcMemWrite,
		bpfEvtLSMFimUnlink, bpfEvtLSMFimRename, bpfEvtLSMFimSetattr:
		return "file_events"
	case bpfEvtNetConn, bpfEvtNetAccept, bpfEvtNetBind, bpfEvtNetClose,
		bpfEvtDNSQuery:
		return "net_events"
	case bpfEvtPtrace, bpfEvtSignal, bpfEvtModule, bpfEvtModuleUnload,
		bpfEvtMount, bpfEvtUnshare, bpfEvtMadvise, bpfEvtBPFLoad,
		bpfEvtBPFMapAccess, bpfEvtCgroupAttach, bpfEvtCgroupMkdir,
		bpfEvtSeccomp, bpfEvtPrivilege:
		return "sec_events"
	case bpfEvtSchedSwitch, bpfEvtSchedWakeup, bpfEvtSchedMigrate:
		return "sched_events"
	case bpfEvtTLSHello:
		return "tls_events"
	}
	return ""
}

// kernelStatsCacheTTL bounds how often Stats() re-reads the maps.
//
// Stats() is on a health and metrics path that callers poll, and a read is 72
// per-CPU map lookups. One read a second is far more resolution than any
// consumer of DriverStats uses, and it keeps a hot caller from turning a
// diagnostic into a cost.
const kernelStatsCacheTTL = time.Second

type kernelStatsCache struct {
	mu     sync.Mutex
	at     time.Time
	report KernelLossReport
}

// KernelEventLossReport reads the in-kernel accounting maps and totals them.
//
// Per-CPU values are summed: the kernel increments the slot belonging to the
// CPU the handler ran on, so a single CPU's view would under-report by the
// number of cores.
func (d *EBPFDriver) KernelEventLossReport() KernelLossReport {
	if d == nil {
		return KernelLossReport{Reason: "no eBPF driver instance"}
	}
	d.mu.RLock()
	coll := d.coll
	d.mu.RUnlock()
	if coll == nil {
		return KernelLossReport{Reason: "no eBPF collection loaded"}
	}

	statsMap, ok := coll.Maps[kernelEventStatsMap]
	if !ok || statsMap == nil {
		return KernelLossReport{Reason: fmt.Sprintf(
			"the loaded object has no %q map, so the kernel is not counting ring buffer losses; rebuild the object from this tree (make ebpf ebpf-link)",
			kernelEventStatsMap)}
	}

	out := KernelLossReport{
		Available:   true,
		ByRing:      map[string]uint64{},
		FilterDrops: map[string]uint64{},
	}

	for typ := uint32(0); typ < edrEventTypeMax; typ++ {
		var percpu []bpfEventStats
		if err := statsMap.Lookup(&typ, &percpu); err != nil {
			continue
		}
		var row KernelEventLoss
		for _, v := range percpu {
			row.Submitted += v.Submitted
			row.ReserveFailed += v.ReserveFailed
		}
		if row.Submitted == 0 && row.ReserveFailed == 0 {
			continue
		}
		row.Type = typ
		row.Ring = ringForEventType(typ)
		row.Category = string(linuxCapabilityForEventType(typ))
		out.ByType = append(out.ByType, row)
		out.TotalSubmitted += row.Submitted
		out.TotalReserveFailed += row.ReserveFailed
		if row.ReserveFailed > 0 && row.Ring != "" {
			out.ByRing[row.Ring] += row.ReserveFailed
		}
	}

	if filterMap, ok := coll.Maps[kernelFilterStatsMap]; ok && filterMap != nil {
		for sub := uint32(0); sub < edrSubsysMax; sub++ {
			var percpu []uint64
			if err := filterMap.Lookup(&sub, &percpu); err != nil {
				continue
			}
			var n uint64
			for _, v := range percpu {
				n += v
			}
			if n == 0 {
				continue
			}
			name, known := edrSubsystemNames[sub]
			if !known {
				name = fmt.Sprintf("subsystem_%d", sub)
			}
			out.FilterDrops[name] = n
		}
	}

	// Loudest loss first, then by type, so a failure message leads with
	// the stream that is actually losing records.
	sort.Slice(out.ByType, func(i, j int) bool {
		if out.ByType[i].ReserveFailed != out.ByType[j].ReserveFailed {
			return out.ByType[i].ReserveFailed > out.ByType[j].ReserveFailed
		}
		return out.ByType[i].Type < out.ByType[j].Type
	})
	return out
}

// kernelEventLossCached is KernelEventLossReport behind kernelStatsCacheTTL.
func (d *EBPFDriver) kernelEventLossCached() KernelLossReport {
	if d == nil {
		return KernelLossReport{}
	}
	d.kernelStats.mu.Lock()
	defer d.kernelStats.mu.Unlock()
	if !d.kernelStats.at.IsZero() && time.Since(d.kernelStats.at) < kernelStatsCacheTTL {
		return d.kernelStats.report
	}
	d.kernelStats.report = d.KernelEventLossReport()
	d.kernelStats.at = time.Now()
	return d.kernelStats.report
}

// kernelLossForCategory totals the records the kernel threw away for one
// capability category, plus what it submitted, so a report row can say which.
func (r KernelLossReport) kernelLossForCategory(cat CapabilityCategory) (submitted, lost uint64) {
	for _, row := range r.ByType {
		if row.Category == string(cat) {
			submitted += row.Submitted
			lost += row.ReserveFailed
		}
	}
	return submitted, lost
}

// Summary is a one-paragraph rendering for a log line or a test failure.
func (r KernelLossReport) Summary() string {
	if !r.Available {
		if r.Reason == "" {
			return "kernel event accounting: unavailable"
		}
		return "kernel event accounting: unavailable: " + r.Reason
	}
	var b strings.Builder
	fmt.Fprintf(&b, "kernel event accounting: submitted=%d reserve_failed=%d",
		r.TotalSubmitted, r.TotalReserveFailed)
	if len(r.ByRing) > 0 {
		fmt.Fprintf(&b, "\n  ring buffers that lost records:")
		for _, name := range sortedStringKeys(r.ByRing) {
			fmt.Fprintf(&b, " %s=%d", name, r.ByRing[name])
		}
	}
	if len(r.FilterDrops) > 0 {
		fmt.Fprintf(&b, "\n  in-kernel pid filter drops (the agent's own pid is always filtered):")
		for _, name := range sortedStringKeys(r.FilterDrops) {
			fmt.Fprintf(&b, " %s=%d", name, r.FilterDrops[name])
		}
	}
	if len(r.ByType) == 0 {
		fmt.Fprintf(&b, "\n  no event type has been submitted or lost: every hook that attached has run zero times")
		return b.String()
	}
	fmt.Fprintf(&b, "\n  per event type (type/category: submitted, lost in kernel):")
	for _, row := range r.ByType {
		cat := row.Category
		if cat == "" {
			cat = "uncategorised"
		}
		fmt.Fprintf(&b, "\n    %d/%s via %s: submitted=%d reserve_failed=%d",
			row.Type, cat, row.Ring, row.Submitted, row.ReserveFailed)
	}
	return b.String()
}

func sortedStringKeys(m map[string]uint64) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// assertKernelStatsGeometry checks the compiled object's accounting maps match
// what this file assumes before any count is read from them.
//
// A map whose max_entries shrank would make the loop above read fewer slots
// and silently under-report; one whose value size changed would decode
// garbage. Both are a stale object, which the version gate also catches, but a
// geometry check names the actual mismatch.
func assertKernelStatsGeometry(coll *ebpf.Collection) error {
	if coll == nil {
		return nil
	}
	m, ok := coll.Maps[kernelEventStatsMap]
	if !ok || m == nil {
		return nil
	}
	if got := m.MaxEntries(); got != edrEventTypeMax {
		return fmt.Errorf("%s has %d entries, this build expects %d (EDR_EVENT_TYPE_MAX in common.h)",
			kernelEventStatsMap, got, edrEventTypeMax)
	}
	if got, want := m.ValueSize(), uint32(16); got != want {
		return fmt.Errorf("%s values are %d bytes, struct edr_event_stats is %d",
			kernelEventStatsMap, got, want)
	}
	return nil
}
