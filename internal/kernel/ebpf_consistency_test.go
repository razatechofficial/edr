package kernel

// Consistency tests over the eBPF objects and the Linux loader.
//
// These exist because the monitoring layer can fail silently in four ways that
// no amount of unit testing of the Go decoders would reveal:
//
//  1. A program compiles into edr.bpf.o, loads into the kernel, and is never
//     attached, because the loader attaches by Go symbol-name prefix and the
//     program's name does not match. The program is live in the kernel. It
//     consumes a program slot. It produces nothing.
//  2. Userspace writes a map the kernel side does not define, so the
//     `if m, ok := d.coll.Maps[name]; ok` guard is false forever and the write
//     is skipped without an error.
//  3. A map is defined in C and read by no program, so whatever userspace puts
//     into it has no effect.
//  4. A ring buffer reader is opened on a buffer no attached program submits
//     to, so the reader goroutine blocks forever and the buffer's locked
//     kernel memory is wasted.
//
// All four were present in the tree. Rather than paper over them, each
// failing item is listed in an allowlist below with the reason it fails and a
// TODO. The tests pass, the debt is enumerated in source, and anything *new*
// that regresses in the same way fails the build. The allowlists are also
// checked for staleness: fix the underlying problem without removing the entry
// and the test fails, so the lists cannot quietly outlive the bugs.
//
// Everything here is pure Go over the source text. It runs on darwin, linux
// and windows, needs no root, no kernel, no BTF and no compiled BPF object.

import (
	"fmt"
	"sort"
	"strings"
	"testing"
)

// knownUnattachedPrograms lists every eBPF program that exists in the sources
// and that the loader never attaches, with the reason.
//
// This list held 23 entries. The loader had two attach paths keyed off Go
// symbol names — attachTracepoints on the "tracepoint__" prefix,
// attachLSMPrograms on "fim_" — and made no kprobe or kretprobe attach call at
// all, so nine kprobes were dead on arrival, seven LSM programs were skipped
// by a prefix check and seven tracepoints were skipped because their C author
// chose a different function name. attachPrograms now plans from each
// program's SEC() string (ebpf_attach.go, ebpfAttachDecision) and calls
// link.Tracepoint, link.Kprobe, link.Kretprobe or link.AttachLSM accordingly,
// so all 23 of those causes are gone.
//
// The three left are not loader defects. They are LSM *enforcement* hooks that
// return -EPERM on a deny-list hit, and the decision not to attach them is
// recorded in ebpfEnforcementLSMPrograms with the full reasoning. Attaching
// one would give the agent the power to block exec, file opens or outbound
// connections host-wide, with no policy surface, no kill switch and no audit
// trail — and because nothing writes their deny-list maps, it would also
// produce no telemetry at all in exchange.
//
// TODO(monitoring): if deny-list enforcement is wanted, it needs a policy
// surface — EventPolicy fields that write exec_deny_list, file_deny_list and
// connect_deny_list, an operator-visible kill switch, and a blocked-action
// event — and then these three attach as part of that feature. Attaching them
// without it is not a fix.
var knownUnattachedPrograms = map[string]string{
	"lsm_bprm_check":     "SEC(lsm/bprm_check_security); enforcement hook, deliberately not attached. It returns -EPERM when the executable path is in exec_deny_list, which would block process execution host-wide, and it submits to lsm_events only on that same deny hit. Nothing in the agent writes exec_deny_list, so attaching it today buys zero telemetry and risks blocking execs",
	"lsm_file_open":      "SEC(lsm/file_open); enforcement hook, deliberately not attached. Returns -EPERM on a file_deny_list hit, which would block opens host-wide, and emits only on that hit. Nothing writes file_deny_list. It would also run a 256-byte-key hash lookup on every open(2) on the host to decide to do nothing",
	"lsm_socket_connect": "SEC(lsm/socket_connect); enforcement hook, deliberately not attached. Returns -EPERM on a connect_deny_list hit, which would block outbound connections host-wide, and emits only on that hit. Nothing writes connect_deny_list",
}

// knownGoMapsMissingFromC lists maps userspace writes that no .c file defines.
//
// The write sites are guarded by `if m, ok := d.coll.Maps[name]; ok`, so a
// missing map is not an error at runtime — the guard is simply false and the
// policy silently does not reach the kernel.
//
// TODO(monitoring): either define these maps in C and have the programs read
// them, or delete the userspace write and the EventPolicy fields that feed it.
// Leaving a write to a nonexistent map is worse than either, because the
// policy surface claims a control that does nothing.
var knownGoMapsMissingFromC = map[string]string{
	"policy_config": "driver_linux.go syncPolicyToMaps packs seven EventPolicy booleans into a flags word and writes key 0, but no .c file defines policy_config. The per-category enable/disable policy never reaches the kernel; filtering happens only in processRecord in userspace, after the event has already cost a ringbuf slot",
	"mute_pids":     "driver_linux.go syncPolicyToMaps writes EventPolicy.MutePIDs here, but no .c file defines mute_pids. PID muting is still effective because installSelfFilter writes the same PIDs into the four per-subsystem *_pid_filter maps that do exist and are read; this write is redundant rather than harmful, but it is dead",
}

// knownUnreadMaps lists maps defined in C that no C program reads.
//
// TODO(monitoring): have file_monitor.c's open/write/unlink/rename programs
// consult path_filter before reserving a ringbuf slot, which is what the
// userspace write site's comment already claims happens.
var knownUnreadMaps = map[string]string{
	"path_filter": "defined in file_monitor.c and read by no program. driver_linux.go syncPolicyToMaps clears and repopulates it from EventPolicy.FIMPaths on every policy sync, and its comment states the kernel drops file events outside those prefixes before they hit userspace. It does not: every file event is reserved, submitted, and filtered in userspace or not at all",
}

// knownRingbufsWithoutAttachedProducer lists ring buffers a Go reader opens
// where the C programs that submit to them are never attached.
//
// It is empty, and that is the measurable result of attaching by SEC().
// lsm_events, sched_events and tls_events each had a Go reader, a declared
// 1<<24-byte buffer and no reachable producer — 48 MiB of locked kernel memory
// and three goroutines blocked on reader.Read() forever. All three now have at
// least one attached producer:
//
//	lsm_events   — lsm_task_kill and lsm_kernel_module_request, the two
//	               observe-only programs in lsm_hooks.c, attach via
//	               link.AttachLSM. The file's other three programs are
//	               enforcement hooks and stay out (see
//	               knownUnattachedPrograms), but they were never the ones
//	               that would have filled this buffer: they submit only on a
//	               deny-list hit.
//	sched_events — edr_tp_sched_switch, edr_tp_sched_wakeup and
//	               edr_tp_sched_migrate_task attach from their
//	               SEC("tracepoint/sched/...") strings instead of being
//	               skipped for not being called tracepoint__sched__*.
//	tls_events   — kp_tls_tcp_sendmsg attaches via link.Kprobe.
//
// Keep it empty. An entry here means a reader is spawned for a buffer nothing
// can fill, and openReaders has no way to know that.
var knownRingbufsWithoutAttachedProducer = map[string]string{}

func loadEBPFConsistencyFixtures(t *testing.T) (*EBPFSources, *LoaderModel) {
	t.Helper()
	src, err := ParseEBPFSources(EBPFSourceDir())
	if err != nil {
		t.Fatalf("parsing ebpf sources: %v", err)
	}
	if len(src.Programs) == 0 {
		t.Fatal("parsed zero eBPF programs; the SEC() parser has stopped matching the sources")
	}
	if len(src.Maps) == 0 {
		t.Fatal("parsed zero eBPF maps; the SEC(\".maps\") parser has stopped matching the sources")
	}
	model, err := ParseLoaderModel(".")
	if err != nil {
		t.Fatalf("parsing loader model: %v", err)
	}
	if len(model.WrittenMaps) == 0 {
		t.Fatal("parsed zero userspace map writes; the coll.Maps[\"...\"] / selfFilterMaps extraction has stopped matching driver_linux.go")
	}
	if len(model.ReaderRingbufs) == 0 {
		t.Fatal("parsed zero ring buffer readers; the readerMaps extraction has stopped matching openReaders in driver_linux.go")
	}
	return src, model
}

// TestEBPFEveryProgramIsAttachedOrAllowlisted is assertion 1: a program that
// exists either has an attach path or is named in knownUnattachedPrograms with
// a reason. Adding a program without an attach path fails here.
func TestEBPFEveryProgramIsAttachedOrAllowlisted(t *testing.T) {
	src, _ := loadEBPFConsistencyFixtures(t)

	attached, unattached := src.AttachedPrograms()
	t.Logf("eBPF programs: %d total, %d attached, %d unattached (%d allowlisted)",
		len(src.Programs), len(attached), len(unattached), len(knownUnattachedPrograms))

	for _, p := range unattached {
		reason, ok := knownUnattachedPrograms[p.Name]
		if !ok {
			t.Errorf("program %s (%s:%d, SEC(%q)) is compiled but the loader makes no attach call for it, and it is not on knownUnattachedPrograms.\n"+
				"attachPrograms plans from the SEC() string via ebpfAttachDecision, which handles tracepoint/, kprobe/, kretprobe/ and lsm/ sections.\n"+
				"Either teach ebpfAttachDecision this section family, or add the program to knownUnattachedPrograms with the reason it is left out on purpose.",
				p.Name, p.File, p.Line, p.Section)
			continue
		}
		if strings.TrimSpace(reason) == "" {
			t.Errorf("program %s is allowlisted with an empty reason; state why it cannot attach", p.Name)
		}
	}

	assertAllowlistNotStale(t, "knownUnattachedPrograms", keysOf(knownUnattachedPrograms), func(name string) bool {
		for _, p := range unattached {
			if p.Name == name {
				return true
			}
		}
		return false
	}, "the program now attaches, or no longer exists")
}

// TestEBPFEveryGoWrittenMapIsDeclaredInC is assertion 2: every map userspace
// puts entries into is defined by at least one .c file. policy_config and
// mute_pids fail today and are allowlisted.
func TestEBPFEveryGoWrittenMapIsDeclaredInC(t *testing.T) {
	src, model := loadEBPFConsistencyFixtures(t)

	t.Logf("userspace writes %d maps: %s", len(model.WrittenMaps), strings.Join(model.WrittenMaps, ", "))

	var missing []string
	for _, name := range model.WrittenMaps {
		if _, ok := src.MapByName(name); ok {
			continue
		}
		missing = append(missing, name)
		reason, listed := knownGoMapsMissingFromC[name]
		if !listed {
			t.Errorf("userspace writes map %q but no .c file in %s defines it.\n"+
				"The write site is guarded by `if m, ok := d.coll.Maps[%q]; ok`, so this does not error at runtime: the guard is false and the write is skipped silently.\n"+
				"Either define the map in C and read it from a program, delete the userspace write, or add it to knownGoMapsMissingFromC with the reason.",
				name, EBPFSourceDir(), name)
			continue
		}
		if strings.TrimSpace(reason) == "" {
			t.Errorf("map %q is allowlisted with an empty reason", name)
		}
	}

	assertAllowlistNotStale(t, "knownGoMapsMissingFromC", keysOf(knownGoMapsMissingFromC), func(name string) bool {
		return containsString(missing, name)
	}, "the map is now defined in C, or userspace no longer writes it")
}

// TestEBPFEveryDeclaredMapIsReadByAProgram is assertion 3: a map defined in C
// is referenced by at least one C program. path_filter fails today.
func TestEBPFEveryDeclaredMapIsReadByAProgram(t *testing.T) {
	src, _ := loadEBPFConsistencyFixtures(t)

	var unread []string
	for _, m := range src.Maps {
		if len(src.MapRefs[m.Name]) > 0 {
			continue
		}
		unread = append(unread, m.Name)
		reason, listed := knownUnreadMaps[m.Name]
		if !listed {
			t.Errorf("map %q (%s:%d, %s) is defined in C but no program passes &%s to a bpf_map_* or bpf_ringbuf_* helper.\n"+
				"Anything userspace writes into it has no effect on what the kernel emits.\n"+
				"Either read it from a program or add it to knownUnreadMaps with the reason.",
				m.Name, m.File, m.Line, m.Type, m.Name)
			continue
		}
		if strings.TrimSpace(reason) == "" {
			t.Errorf("map %q is allowlisted with an empty reason", m.Name)
		}
	}

	t.Logf("eBPF maps: %d defined, %d read by no program (%d allowlisted)",
		len(src.Maps), len(unread), len(knownUnreadMaps))

	assertAllowlistNotStale(t, "knownUnreadMaps", keysOf(knownUnreadMaps), func(name string) bool {
		return containsString(unread, name)
	}, "the map is now read by a program, or no longer defined")
}

// TestEBPFEveryReaderRingbufHasAnAttachedProducer is assertion 4: for every
// ring buffer openReaders opens, at least one program that submits to it is
// actually attached.
//
// The "attached" half matters. All three allowlisted buffers do have C
// programs that call bpf_ringbuf_reserve on them, so a check that only looked
// at the C side would pass while the readers still blocked forever. The
// producer has to be reachable to count.
func TestEBPFEveryReaderRingbufHasAnAttachedProducer(t *testing.T) {
	src, model := loadEBPFConsistencyFixtures(t)

	attachedSet := make(map[string]bool)
	for _, p := range src.Programs {
		if ok, _ := LoaderAttachesProgram(p); ok {
			attachedSet[p.Name] = true
		}
	}

	var starved []string
	for _, name := range model.ReaderRingbufs {
		if _, defined := src.MapByName(name); !defined {
			// openReaders skips a ring buffer the object does not
			// contain, so this is not a silent no-op. Assertion 2
			// covers map names userspace writes.
			t.Logf("ring buffer %q has a Go reader but is not defined in C; openReaders skips it", name)
			continue
		}
		producers := src.RingbufProducers[name]
		var live []string
		for _, p := range producers {
			if attachedSet[p] {
				live = append(live, p)
			}
		}
		if len(live) > 0 {
			t.Logf("ring buffer %q: %d producer(s), %d attached (%s)", name, len(producers), len(live), strings.Join(live, ", "))
			continue
		}
		starved = append(starved, name)
		reason, listed := knownRingbufsWithoutAttachedProducer[name]
		if !listed {
			t.Errorf("ring buffer %q has a Go reader in openReaders but no attached producer.\n"+
				"C programs that submit to it: %s. None of them is attached by the loader.\n"+
				"The reader goroutine blocks on reader.Read() forever and the buffer's locked kernel memory is wasted.\n"+
				"Either attach a producer or add it to knownRingbufsWithoutAttachedProducer with the reason.",
				name, producerList(producers))
			continue
		}
		if strings.TrimSpace(reason) == "" {
			t.Errorf("ring buffer %q is allowlisted with an empty reason", name)
		}
	}

	assertAllowlistNotStale(t, "knownRingbufsWithoutAttachedProducer", keysOf(knownRingbufsWithoutAttachedProducer), func(name string) bool {
		return containsString(starved, name)
	}, "the ring buffer now has an attached producer, or no longer has a Go reader")
}

// TestEBPFLoaderAttachMechanismsUnchanged asserts the loader still attaches
// from the SEC() string, and still has all four attach calls.
//
// LoaderAttachesProgram no longer models the loader — it calls the loader's own
// ebpfAttachDecision — so the drift this test used to guard against is gone by
// construction. What is left to guard is the loader's shape: that the four
// link calls are present, that attach is planned from the section rather than
// from a Go symbol name, and in particular that nobody reintroduces the symbol
// prefix matching. The prefix checks are what made 23 programs silent, and
// they are easy to put back because "attach the fim_ ones" reads like intent.
func TestEBPFLoaderAttachMechanismsUnchanged(t *testing.T) {
	_, model := loadEBPFConsistencyFixtures(t)

	mustContain := []struct {
		needle string
		why    string
	}{
		{"ebpfAttachDecision(", "attach is planned from the SEC() string, not from the Go symbol name"},
		{"d.sectionForProgram(", "attachPrograms reads each program's section from what was loaded"},
		{"link.Tracepoint(", "tracepoint attach call"},
		{"link.Kprobe(", "kprobe attach call — nine programs depend on it"},
		{"link.Kretprobe(", "kretprobe attach call — kretp_udp_recvmsg depends on it"},
		{"link.AttachLSM(", "LSM attach call"},
	}
	for _, c := range mustContain {
		if !strings.Contains(model.Source, c.needle) {
			t.Errorf("the Linux loader no longer contains %q (%s).\n"+
				"If an attach call was removed, every program that needed it is silent again; add its programs to knownUnattachedPrograms with the reason, or restore the call.",
				c.needle, c.why)
		}
	}

	// Symbol-name prefix matching is the defect this change removed. Any
	// reappearance makes a program's attachability depend on what its C
	// author called the function, which is exactly how DNS, scheduler and
	// TLS telemetry went dark without anyone noticing.
	mustNotContain := []struct {
		needle string
		why    string
	}{
		{`"tracepoint__"`, "tracepoint attach keyed off a Go symbol prefix"},
		{`"fim_"`, "LSM attach keyed off a Go symbol prefix"},
	}
	for _, c := range mustNotContain {
		if strings.Contains(model.Source, c.needle) {
			t.Errorf("the Linux loader contains the literal %s (%s).\n"+
				"Attach must be decided by ebpfAttachDecision over the program's SEC() string. A symbol-name prefix check silently excludes any program whose C function is named differently, which is how 23 of 62 programs came to load into the kernel and never fire.",
				c.needle, c.why)
		}
	}
}

// TestEBPFConsistencyAllowlistsAreDocumented asserts each allowlist entry
// carries a usable reason, independently of whether its assertion currently
// fires. An entry whose reason is a bare restatement of the name is not a
// reason.
func TestEBPFConsistencyAllowlistsAreDocumented(t *testing.T) {
	lists := map[string]map[string]string{
		"knownUnattachedPrograms":              knownUnattachedPrograms,
		"knownGoMapsMissingFromC":              knownGoMapsMissingFromC,
		"knownUnreadMaps":                      knownUnreadMaps,
		"knownRingbufsWithoutAttachedProducer": knownRingbufsWithoutAttachedProducer,
	}
	const minReasonLen = 30
	for listName, list := range lists {
		for _, name := range sortedStrings(keysOf(list)) {
			reason := strings.TrimSpace(list[name])
			if len(reason) < minReasonLen {
				t.Errorf("%s[%q] reason is %d characters; state what is broken and what the consequence is (at least %d)",
					listName, name, len(reason), minReasonLen)
			}
		}
	}
}

// assertAllowlistNotStale fails for allowlist entries whose underlying problem
// no longer reproduces. Without this the lists accumulate: someone fixes a
// program's attach path, the test still passes, and the entry stays forever
// claiming a bug that is gone.
func assertAllowlistNotStale(t *testing.T, listName string, entries []string, stillFailing func(string) bool, fixedHint string) {
	t.Helper()
	for _, name := range sortedStrings(entries) {
		if stillFailing(name) {
			continue
		}
		t.Errorf("%s[%q] is stale: %s. Remove the entry — the allowlist is a debt register, not a config file.",
			listName, name, fixedHint)
	}
}

func keysOf(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

func sortedStrings(in []string) []string {
	out := append([]string(nil), in...)
	sort.Strings(out)
	return out
}

func containsString(haystack []string, needle string) bool {
	for _, s := range haystack {
		if s == needle {
			return true
		}
	}
	return false
}

func producerList(producers []string) string {
	if len(producers) == 0 {
		return "(none)"
	}
	return fmt.Sprintf("%v", producers)
}
