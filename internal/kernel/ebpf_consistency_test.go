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
// All four are present in the tree today. Rather than paper over them, each
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
// The loader has exactly two attach paths (driver_linux.go: attachTracepoints
// keys off the Go symbol prefix "tracepoint__", attachLSMPrograms off "fim_").
// There is no link.Kprobe or link.Kretprobe call anywhere in the tree, so
// every kprobe and kretprobe program below is dead on arrival, and every
// tracepoint program whose C function was named something other than
// tracepoint__<group>__<name> is skipped by the prefix check.
//
// TODO(monitoring): the fix is to attach by SEC() rather than by Go symbol
// name — the section string already states the attach type and target for
// every program here — and to add link.Kprobe/link.Kretprobe support. Until
// then DNS, UDP, TCP-close, byte-count, TLS-SNI, scheduler and LSM telemetry
// are compiled, loaded and silent.
var knownUnattachedPrograms = map[string]string{
	// kprobe/kretprobe: no link.Kprobe or link.Kretprobe call exists.
	// TODO(monitoring): add kprobe attach support to the loader.
	"kprobe_mem_write":       "SEC(kprobe/mem_write); loader makes no link.Kprobe call, so /proc/pid/mem write telemetry never fires",
	"kp_tcp_v4_connect":      "SEC(kprobe/tcp_v4_connect); no link.Kprobe call. IPv4 connect detail (socket-level, post-DNS) is lost; only the connect(2) tracepoint survives",
	"kp_tcp_v6_connect":      "SEC(kprobe/tcp_v6_connect); no link.Kprobe call. IPv6 connect detail is lost",
	"kp_udp_sendmsg":         "SEC(kprobe/udp_sendmsg); no link.Kprobe call. All outbound UDP telemetry is lost, which includes DNS egress",
	"kp_udp_recvmsg":         "SEC(kprobe/udp_recvmsg); no link.Kprobe call. Inbound UDP telemetry is lost",
	"kretp_udp_recvmsg":      "SEC(kretprobe/udp_recvmsg); no link.Kretprobe call. The return-side half of UDP receive, which carries the payload length, is lost",
	"kp_tcp_close":           "SEC(kprobe/tcp_close); no link.Kprobe call. Connection teardown and the byte counts attached to it are never reported",
	"kp_inet_sock_set_state": "SEC(kprobe/inet_sock_set_state); no link.Kprobe call. TCP state transitions are never reported",
	"kp_tls_tcp_sendmsg":     "SEC(kprobe/tcp_sendmsg); no link.Kprobe call. TLS ClientHello SNI extraction never runs, and tls_events has no attached producer as a result",

	// LSM programs not named fim_*: attachLSMPrograms skips them.
	// TODO(monitoring): decide per program whether it should attach as an
	// observer; lsm_hooks.c submits to lsm_events, which has a Go reader.
	"lsm_bprm_check":            "SEC(lsm/bprm_check_security); attachLSMPrograms only attaches the fim_ prefix, so this is skipped. It submits to lsm_events, which a Go reader opens",
	"lsm_file_open":             "SEC(lsm/file_open); skipped by the fim_ prefix check. Submits to lsm_events",
	"lsm_socket_connect":        "SEC(lsm/socket_connect); skipped by the fim_ prefix check. Submits to lsm_events",
	"lsm_task_kill":             "SEC(lsm/task_kill); skipped by the fim_ prefix check. Submits to lsm_events",
	"lsm_kernel_module_request": "SEC(lsm/kernel_module_request); skipped by the fim_ prefix check. Submits to lsm_events",
	"lsm_bpf_prog":              "SEC(lsm/bpf); skipped by the fim_ prefix check. BPF-loading-BPF detection never fires",
	"lsm_bpf_map_prog":          "SEC(lsm/bpf_map); skipped by the fim_ prefix check. BPF map tampering detection never fires",

	// Tracepoint programs whose C function name does not start with
	// tracepoint__, so attachTracepoints' prefix check skips them even
	// though the SEC() names a perfectly attachable tracepoint.
	// TODO(monitoring): rename to tracepoint__<group>__<name>, or switch the
	// loader to attach from SEC(). Renaming is the one-line fix.
	"tp_dns_sendto":             "SEC(tracepoint/syscalls/sys_enter_sendto) but named tp_dns_sendto, so the tracepoint__ prefix check skips it. This is the only DNS query program; DNS telemetry from eBPF is entirely absent. Note syscall_monitor.c declares the same tracepoint as tracepoint__syscalls__sys_enter_sendto and that one does attach, so the tracepoint is occupied but the DNS parsing never runs",
	"tp_cgroup_attach":          "SEC(tracepoint/cgroup/cgroup_attach_task) but named tp_cgroup_attach; skipped by the tracepoint__ prefix check. Container escape signal is absent",
	"tp_cgroup_mkdir":           "SEC(tracepoint/cgroup/cgroup_mkdir) but named tp_cgroup_mkdir; skipped by the prefix check",
	"tp_seccomp":                "SEC(tracepoint/syscalls/sys_enter_seccomp) but named tp_seccomp; skipped by the prefix check",
	"edr_tp_sched_switch":       "SEC(tracepoint/sched/sched_switch) but named edr_tp_sched_switch; skipped by the prefix check. sched_events has a Go reader and a passing decoder unit test for data that cannot arrive",
	"edr_tp_sched_wakeup":       "SEC(tracepoint/sched/sched_wakeup) but named edr_tp_sched_wakeup; skipped by the prefix check",
	"edr_tp_sched_migrate_task": "SEC(tracepoint/sched/sched_migrate_task) but named edr_tp_sched_migrate_task; skipped by the prefix check",
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
// Each costs a blocked goroutine plus the buffer's locked kernel memory. The
// three below are 1<<24 bytes each as declared, so 48 MiB of locked memory for
// buffers nothing can fill. (The brief's figure of 24 MB counts two of them;
// the declarations say 16 MiB each.)
//
// TODO(monitoring): attaching the producers fixes all three at once. Until
// then, openReaders should skip a ring buffer with no attached producer rather
// than spawn a reader for it.
var knownRingbufsWithoutAttachedProducer = map[string]string{
	"lsm_events":   "lsm_hooks.c submits from five lsm/* programs, none of which attach: attachLSMPrograms only attaches the fim_ prefix",
	"sched_events": "sched_monitor.c submits from three tracepoint/sched/* programs named edr_tp_*, none of which match the tracepoint__ prefix check",
	"tls_events":   "tls_sni_monitor.c submits from kp_tls_tcp_sendmsg, a kprobe, and the loader makes no link.Kprobe call",
}

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
			t.Errorf("program %s (%s:%d, SEC(%q)) is compiled but never attached, and is not on knownUnattachedPrograms.\n"+
				"The loader attaches only Go symbols prefixed %q (as tracepoint__<group>__<name>) and LSM symbols prefixed %q.\n"+
				"Either give it an attach path in driver_linux.go, rename it to match a prefix, or add it to knownUnattachedPrograms with the reason it cannot attach yet.",
				p.Name, p.File, p.Line, p.Section, ebpfTracepointPrefix, ebpfLSMFimPrefix)
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

// TestEBPFLoaderAttachMechanismsUnchanged guards LoaderAttachesProgram against
// drift in the loader it models.
//
// LoaderAttachesProgram is a model, not a reading, of driver_linux.go. If
// someone adds link.Kprobe support — which is the fix for nine of the entries
// in knownUnattachedPrograms — the model would keep reporting those programs
// as unattached and the allowlist staleness check would not fire. This test
// fails instead, pointing at the model.
func TestEBPFLoaderAttachMechanismsUnchanged(t *testing.T) {
	_, model := loadEBPFConsistencyFixtures(t)

	mustContain := []struct {
		needle string
		why    string
	}{
		{`const prefix = "` + ebpfTracepointPrefix + `"`, "attachTracepoints keys off this Go symbol prefix"},
		{`strings.HasPrefix(name, "` + ebpfLSMFimPrefix + `")`, "attachLSMPrograms keys off this Go symbol prefix"},
		{"link.Tracepoint(", "tracepoint attach call"},
		{"link.AttachLSM(", "LSM attach call"},
	}
	for _, c := range mustContain {
		if !strings.Contains(model.Source, c.needle) {
			t.Errorf("driver_linux.go no longer contains %q (%s).\n"+
				"LoaderAttachesProgram in ebpf_consistency_model_test.go models the loader's attach predicates and is now out of date; update it to match.",
				c.needle, c.why)
		}
	}

	// These are the attach calls whose absence is the reason nine programs
	// cannot attach. When one appears, the model has to learn about it.
	mustNotContain := []struct {
		needle string
		why    string
	}{
		{"link.Kprobe(", "kprobe attach"},
		{"link.Kretprobe(", "kretprobe attach"},
	}
	for _, c := range mustNotContain {
		if strings.Contains(model.Source, c.needle) {
			t.Errorf("driver_linux.go now calls %s (%s), which LoaderAttachesProgram does not model.\n"+
				"Teach LoaderAttachesProgram to recognise kprobe/kretprobe sections, then remove the programs it now attaches from knownUnattachedPrograms.",
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
