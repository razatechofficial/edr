package kernel

// Tests for the SEC()-driven attach planner.
//
// These run on every OS and need no kernel, which is the reason the planner
// was put in a file with no build tag. The attach calls themselves cannot be
// tested without a kernel; the decision of *which* call to make for which
// program is where the 23-program defect lived, and that is all string
// handling.

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseEBPFSection(t *testing.T) {
	t.Parallel()

	cases := []struct {
		section string
		want    ebpfAttachTarget
	}{
		{"tracepoint/syscalls/sys_enter_execve", ebpfAttachTarget{Kind: ebpfAttachTracepoint, Group: "syscalls", Name: "sys_enter_execve"}},
		{"tracepoint/sched/sched_switch", ebpfAttachTarget{Kind: ebpfAttachTracepoint, Group: "sched", Name: "sched_switch"}},
		{"tracepoint/cgroup/cgroup_mkdir", ebpfAttachTarget{Kind: ebpfAttachTracepoint, Group: "cgroup", Name: "cgroup_mkdir"}},
		{"kprobe/tcp_close", ebpfAttachTarget{Kind: ebpfAttachKprobe, Symbol: "tcp_close"}},
		{"kretprobe/udp_recvmsg", ebpfAttachTarget{Kind: ebpfAttachKretprobe, Symbol: "udp_recvmsg"}},
		{"lsm/path_unlink", ebpfAttachTarget{Kind: ebpfAttachLSM, Hook: "path_unlink"}},
		{"lsm/bpf_map", ebpfAttachTarget{Kind: ebpfAttachLSM, Hook: "bpf_map"}},
	}
	for _, tc := range cases {
		got, err := parseEBPFSection(tc.section)
		if err != nil {
			t.Errorf("parseEBPFSection(%q) returned %v, want a target", tc.section, err)
			continue
		}
		if got != tc.want {
			t.Errorf("parseEBPFSection(%q) = %+v, want %+v", tc.section, got, tc.want)
		}
	}
}

// TestParseEBPFSectionRejectsUnknown asserts a section the loader has no
// attach call for is an error and not a silent skip.
//
// A silent skip is precisely the failure this change removed: a program that
// loads into the kernel, consumes a program slot and never fires, with nothing
// anywhere saying so. An error here becomes a recorded miss with a reason on
// the capability report.
func TestParseEBPFSectionRejectsUnknown(t *testing.T) {
	t.Parallel()

	bad := []string{
		"",
		"tracepoint",
		"tracepoint/",
		"tracepoint/syscalls",
		"kprobe",
		"kprobe/",
		"kprobe/tcp/close",
		"lsm/",
		"fentry/vfs_write",
		"uprobe//bin/bash:readline",
		"socket",
		"xdp/eth0",
	}
	for _, section := range bad {
		if got, err := parseEBPFSection(section); err == nil {
			t.Errorf("parseEBPFSection(%q) = %+v with no error; an unrecognised section must be reported, not silently skipped", section, got)
		}
	}
}

// TestEBPFAttachDecisionCoversEverySourceProgram walks the real C sources and
// asserts the planner reaches a decision for every program, with a stated
// reason whenever it decides not to attach.
//
// This is the assertion that would have caught the original defect. It does
// not care which programs attach — the consistency tests own that — only that
// no program falls through the planner without either an attach call or a
// recorded reason.
func TestEBPFAttachDecisionCoversEverySourceProgram(t *testing.T) {
	src, err := ParseEBPFSources(EBPFSourceDir())
	if err != nil {
		t.Fatalf("parsing ebpf sources: %v", err)
	}
	if len(src.Programs) == 0 {
		t.Fatal("parsed zero programs")
	}

	byKind := make(map[ebpfAttachKind]int)
	skipped := 0
	for _, p := range src.Programs {
		target, attempt, skip := ebpfAttachDecision(p.Name, p.Section)
		if !attempt {
			skipped++
			if strings.TrimSpace(skip) == "" {
				t.Errorf("program %s (SEC(%q)) is not attached and the planner gives no reason; the capability report would show the category dark with no cause", p.Name, p.Section)
			}
			continue
		}
		if target.Kind == "" {
			t.Errorf("program %s (SEC(%q)) is planned for attach with no attach kind", p.Name, p.Section)
		}
		if target.String() == "unknown target" {
			t.Errorf("program %s (SEC(%q)) has a target that cannot be described: %+v", p.Name, p.Section, target)
		}
		byKind[target.Kind]++
	}

	t.Logf("attach plan over %d programs: %d tracepoint, %d kprobe, %d kretprobe, %d lsm, %d not attached",
		len(src.Programs), byKind[ebpfAttachTracepoint], byKind[ebpfAttachKprobe],
		byKind[ebpfAttachKretprobe], byKind[ebpfAttachLSM], skipped)

	// The kprobe and kretprobe counts are the heart of the change: before
	// it, the loader made no kprobe attach call at all, so these nine
	// programs were loaded and silent. If either count goes to zero the
	// planner has stopped recognising a section family.
	if byKind[ebpfAttachKprobe] == 0 {
		t.Error("no program is planned as a kprobe; the sources contain eight SEC(kprobe/...) programs and the planner has stopped recognising them")
	}
	if byKind[ebpfAttachKretprobe] == 0 {
		t.Error("no program is planned as a kretprobe; kretp_udp_recvmsg carries SEC(kretprobe/udp_recvmsg)")
	}
}

// TestEBPFEnforcementLSMProgramsExistAndAreNotObservers keeps the
// deliberately-unattached set honest against the sources.
//
// Two ways this could rot: a named program could be renamed or removed, in
// which case the entry is a stale claim about code that no longer exists; or
// the program could be rewritten as an observer that no longer returns -EPERM,
// in which case the reason for leaving it out is gone and it should be
// attached. Both are checked against the C text.
func TestEBPFEnforcementLSMProgramsExistAndAreNotObservers(t *testing.T) {
	src, err := ParseEBPFSources(EBPFSourceDir())
	if err != nil {
		t.Fatalf("parsing ebpf sources: %v", err)
	}

	bySection := make(map[string]EBPFProgram, len(src.Programs))
	for _, p := range src.Programs {
		bySection[p.Name] = p
	}

	for name, why := range ebpfEnforcementLSMPrograms {
		prog, ok := bySection[name]
		if !ok {
			t.Errorf("ebpfEnforcementLSMPrograms names %q, which no .c file in %s declares; remove the stale entry", name, EBPFSourceDir())
			continue
		}
		if !strings.HasPrefix(prog.Section, "lsm/") {
			t.Errorf("ebpfEnforcementLSMPrograms names %q but its SEC() is %q, not an lsm/ section", name, prog.Section)
		}
		if strings.TrimSpace(why) == "" {
			t.Errorf("ebpfEnforcementLSMPrograms[%q] has no reason; state what it enforces and what attaching it would do", name)
		}
		if !ebpfProgramReturnsEPERM(t, prog) {
			t.Errorf("ebpfEnforcementLSMPrograms names %q, but its body no longer returns -EPERM.\n"+
				"If it has become an observe-only hook there is no reason to leave it unattached: remove it from ebpfEnforcementLSMPrograms, from ebpfUnattachableHooks and from knownUnattachedPrograms so its telemetry starts flowing.", name)
		}
	}
}

// ebpfProgramReturnsEPERM reports whether the named program's body contains a
// -EPERM return, read straight out of the C file.
func ebpfProgramReturnsEPERM(t *testing.T, prog EBPFProgram) bool {
	t.Helper()
	body, err := ebpfProgramBodyText(prog)
	if err != nil {
		t.Errorf("reading body of %s: %v", prog.Name, err)
		return true // do not fail the caller's assertion on a read error
	}
	return strings.Contains(body, "-EPERM")
}

// ebpfProgramBodyText returns the C text of one program: the lines from its
// SEC() declaration up to the next SEC() or end of file.
//
// Reading the C rather than keeping a Go-side copy of what each program does
// is what makes the assertions above catch a rewrite of the C.
func ebpfProgramBodyText(prog EBPFProgram) (string, error) {
	f, err := os.Open(filepath.Join(EBPFSourceDir(), prog.File))
	if err != nil {
		return "", err
	}
	defer f.Close()

	var b strings.Builder
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	line := 0
	in := false
	for sc.Scan() {
		line++
		text := sc.Text()
		if line == prog.Line {
			in = true
			b.WriteString(text)
			b.WriteByte('\n')
			continue
		}
		if !in {
			continue
		}
		if strings.HasPrefix(text, "SEC(\"") {
			break
		}
		b.WriteString(text)
		b.WriteByte('\n')
	}
	if err := sc.Err(); err != nil {
		return "", err
	}
	if !in {
		return "", nil
	}
	return b.String(), nil
}
