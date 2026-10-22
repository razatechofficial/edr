//go:build linux

package kernel

import (
	"os"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// TestLinuxEventTypeRingCoverage asserts every eBPF event type the Go side
// knows about names the ring buffer its records are submitted to.
//
// Without this, a new event type added to common.h would report a kernel loss
// with an empty ring name, and the per-ring total — the number a sizing or
// draining fix is chosen from — would silently omit it. The constant list is
// parsed out of driver_linux.go rather than restated, for the same reason
// TestLinuxEventTypeCategoryCoverage does it: a restated list drifts.
func TestLinuxEventTypeRingCoverage(t *testing.T) {
	raw, err := os.ReadFile("driver_linux.go")
	if err != nil {
		t.Fatalf("reading driver_linux.go: %v", err)
	}

	re := regexp.MustCompile(`(?m)^\s*(bpfEvt[A-Za-z0-9_]*)\s*=\s*(\d+)\s*$`)
	matches := re.FindAllStringSubmatch(string(raw), -1)
	if len(matches) == 0 {
		t.Fatal("parsed no bpfEvt* constants from driver_linux.go; the constant block has moved and this test is no longer checking anything")
	}

	readerMaps := map[string]bool{
		"events": true, "file_events": true, "net_events": true,
		"sec_events": true, "lsm_events": true, "sched_events": true,
		"tls_events": true,
	}

	for _, m := range matches {
		name, valStr := m[1], m[2]
		val, err := strconv.ParseUint(valStr, 10, 32)
		if err != nil {
			t.Errorf("constant %s has unparseable value %q: %v", name, valStr, err)
			continue
		}
		ring := ringForEventType(uint32(val))
		if ring == "" {
			t.Errorf("event type %s (%d) names no ring buffer in ringForEventType.\n"+
				"A reserve failure for it would be counted but not attributed, so the per-ring totals an operator sizes the buffer from would leave it out.",
				name, val)
			continue
		}
		if !readerMaps[ring] {
			t.Errorf("event type %s (%d) names ring %q, which openReaders does not open", name, val, ring)
		}
	}
}

// TestKernelStatsGeometryMatchesCommonHeader asserts the Go side's idea of the
// accounting maps matches the C declaration.
//
// edrEventTypeMax and the bpfEventStats layout are an ABI with the compiled
// object: reading 64 slots from a 32-slot map under-reports, and a value
// struct that grew a field decodes garbage. The loader checks the loaded
// object at runtime; this checks the source they are both built from, so a
// mismatch fails on every OS instead of only on a Linux host with a kernel.
func TestKernelStatsGeometryMatchesCommonHeader(t *testing.T) {
	raw, err := os.ReadFile("../../platform/linux/ebpf/common.h")
	if err != nil {
		t.Fatalf("reading common.h: %v", err)
	}
	src := string(raw)

	wantMax := "#define EDR_EVENT_TYPE_MAX " + strconv.Itoa(edrEventTypeMax)
	if !strings.Contains(src, wantMax) {
		t.Errorf("common.h does not contain %q; edrEventTypeMax in Go is %d and the two must agree or the map is read with the wrong number of slots",
			wantMax, edrEventTypeMax)
	}
	if !strings.Contains(src, "EDR_SUBSYS_MAX      = "+strconv.Itoa(edrSubsysMax)) {
		t.Errorf("common.h does not set EDR_SUBSYS_MAX to %d, which is what edrSubsysMax in Go assumes", edrSubsysMax)
	}

	// struct edr_event_stats must stay two __u64 fields in this order.
	if !strings.Contains(src, "struct edr_event_stats {\n\t__u64 submitted;\n\t__u64 reserve_failed;\n};") {
		t.Error("struct edr_event_stats in common.h is no longer {__u64 submitted; __u64 reserve_failed;}.\n" +
			"bpfEventStats in Go decodes the map value by field offset, so any change here has to be made there too.")
	}
	for _, name := range []string{kernelEventStatsMap, kernelFilterStatsMap} {
		if !strings.Contains(src, "} "+name+" SEC(\".maps\")") {
			t.Errorf("common.h no longer declares the %q map; the driver reads it by that name", name)
		}
	}
}

// TestKernelEventLossReportWithoutCollection proves the report distinguishes
// "no losses" from "cannot tell".
//
// A health surface that reports an unavailable counter as zero is worse than
// one that reports nothing: it asserts the absence of a fault it did not look
// for. That is the exact failure this accounting was added to fix, so it is
// worth a test of its own.
func TestKernelEventLossReportWithoutCollection(t *testing.T) {
	var nilDriver *EBPFDriver
	if rep := nilDriver.KernelEventLossReport(); rep.Available || rep.Reason == "" {
		t.Errorf("nil driver: got available=%v reason=%q, want unavailable with a reason", rep.Available, rep.Reason)
	}

	d := &EBPFDriver{}
	rep := d.KernelEventLossReport()
	if rep.Available {
		t.Error("a driver with no loaded collection reported the accounting as available")
	}
	if !strings.Contains(rep.Summary(), "unavailable") {
		t.Errorf("Summary() = %q, want it to say the accounting is unavailable", rep.Summary())
	}
}

// TestKernelLossForCategoryTotalsEveryType proves a category served by more
// than one event type sums them, and names the ring the loss happened on.
func TestKernelLossForCategoryTotalsEveryType(t *testing.T) {
	rep := KernelLossReport{
		Available: true,
		ByType: []KernelEventLoss{
			{Type: bpfEvtFileDel, Ring: "file_events", Category: string(CapFileDelete), Submitted: 3, ReserveFailed: 7},
			{Type: bpfEvtLSMFimUnlink, Ring: "file_events", Category: string(CapFileDelete), Submitted: 1, ReserveFailed: 2},
			{Type: bpfEvtNetConn, Ring: "net_events", Category: string(CapNetworkConnect), Submitted: 9},
		},
	}

	submitted, lost, ring := rep.kernelLossForCategory(CapFileDelete)
	if submitted != 4 || lost != 9 {
		t.Errorf("file_delete: got submitted=%d lost=%d, want 4 and 9", submitted, lost)
	}
	if ring != "file_events" {
		t.Errorf("file_delete: got ring %q, want file_events", ring)
	}

	if _, lost, _ := rep.kernelLossForCategory(CapNetworkConnect); lost != 0 {
		t.Errorf("network_connect: got lost=%d, want 0", lost)
	}
	if submitted, lost, _ := rep.kernelLossForCategory(CapScheduler); submitted != 0 || lost != 0 {
		t.Errorf("scheduler: got submitted=%d lost=%d for a category with no rows, want 0 and 0", submitted, lost)
	}
}
