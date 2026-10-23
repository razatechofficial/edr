package kernel

// Static model of the Linux eBPF sources and of the loader that attaches them.
//
// This is test-only: the agent itself never parses its own C sources, so none
// of this belongs in the shipped binary. Two test suites share it. The
// consistency tests in ebpf_consistency_test.go assert that every compiled
// program has an attach path and that no map or ring buffer is inert, and
// capability_report_linux_test.go uses the program list to assert the
// capability report's program-to-category table covers every program that
// exists. One parser means the two can never disagree about what is there.
//
// Everything here is pure text parsing over platform/linux/ebpf/*.c and
// internal/kernel/driver_linux.go. It runs on any OS, needs no root, no kernel
// and no compiled BPF object, which is the point: the failures it catches are
// silent no-ops that a Linux-only, root-only test would never run often enough
// to notice.

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// EBPFProgram is one SEC()-annotated program in the eBPF sources.
//
// Name is the C function name, which is also the symbol name the loader sees in
// ebpf.Collection.Programs — that identity is what makes prefix-based attach
// possible, and what makes it fragile.
type EBPFProgram struct {
	Name    string // C function name, e.g. "tracepoint__syscalls__sys_enter_execve"
	Section string // SEC() argument, e.g. "tracepoint/syscalls/sys_enter_execve"
	File    string // base name of the .c file
	Line    int    // 1-based line of the SEC() declaration
}

// EBPFMap is one map defined in the eBPF sources.
//
// Only definitions are recorded. lsm_fim.c forward-declares file_events and
// file_pid_filter with `extern struct { ... } name;` so bpftool can link them
// into the merged object; those carry no SEC(".maps") and are deliberately not
// counted as definitions, because counting them would let a map that nothing
// actually defines look defined.
type EBPFMap struct {
	Name string
	Type string // BPF_MAP_TYPE_* when the definition states one
	File string
	Line int
}

// EBPFSources is the parsed view of platform/linux/ebpf/*.c.
type EBPFSources struct {
	Programs []EBPFProgram
	Maps     []EBPFMap

	// MapRefs maps a map name to the names of the programs whose body (or
	// whose file prologue) passes &map to a bpf_map_* or bpf_ringbuf_*
	// helper. A map with no entry here is read and written by nothing on
	// the kernel side, however much userspace puts into it.
	MapRefs map[string][]string

	// RingbufProducers maps a ring buffer name to the programs that
	// reserve or output into it. A reader with no producer here blocks
	// forever on a buffer nothing ever fills.
	RingbufProducers map[string][]string
}

// LoaderModel is the parsed view of the Go side's map and ring buffer use.
type LoaderModel struct {
	// WrittenMaps are maps userspace puts entries into, taken from the
	// literal d.coll.Maps["name"] lookups and from selfFilterMaps.
	WrittenMaps []string

	// ReaderRingbufs are the ring buffers openReaders() opens a
	// ringbuf.Reader on.
	ReaderRingbufs []string

	// Source is the concatenated Go source the model was parsed from, kept
	// so the attach-mechanism guard can assert against it.
	Source string
}

var (
	// A program is `SEC("...")` on one line and the function on the next,
	// either plain (`int name(ctx)`) or wrapped in BPF_PROG for LSM and
	// fentry-style programs (`int BPF_PROG(name, args...)`).
	reEBPFProgram = regexp.MustCompile(`(?m)^SEC\("([^"]+)"\)[ \t]*\r?\n[ \t]*(?:static[ \t]+)?int[ \t]+(?:BPF_PROG\([ \t]*([A-Za-z_][A-Za-z0-9_]*)|([A-Za-z_][A-Za-z0-9_]*)[ \t]*\()`)

	// A map definition closes an anonymous struct with the map name and
	// SEC(".maps"). `extern struct { ... } name;` has no SEC and so does
	// not match, which is what we want.
	reEBPFMapDef = regexp.MustCompile(`\}[ \t]*([A-Za-z_][A-Za-z0-9_]*)[ \t]*SEC\("\.maps"\)`)

	reEBPFMapType = regexp.MustCompile(`__uint\([ \t]*type[ \t]*,[ \t]*(BPF_MAP_TYPE_[A-Z0-9_]+)`)

	reEBPFMapHelper = regexp.MustCompile(`bpf_map_(?:lookup_elem|update_elem|delete_elem|lookup_and_delete_elem|push_elem|pop_elem|peek_elem)\([ \t]*&([A-Za-z_][A-Za-z0-9_]*)`)
	// A ring buffer submission, through the raw helper or through
	// edr_ringbuf_reserve, the counted wrapper in common.h that every
	// program now goes through. Missing the wrapper would report every
	// ring buffer as having no producer at all.
	reEBPFRingbufCall = regexp.MustCompile(`(?:bpf|edr)_ringbuf_(?:reserve|output)\([ \t]*&([A-Za-z_][A-Za-z0-9_]*)`)

	// Sections that are metadata, not programs.
	reEBPFSECAny = regexp.MustCompile(`(?m)^[^\n]*SEC\("([^"]+)"\)`)

	reGoCollMapLiteral = regexp.MustCompile(`coll\.Maps\["([A-Za-z_][A-Za-z0-9_]*)"\]`)
	reGoSelfFilterMaps = regexp.MustCompile(`(?s)selfFilterMaps\s*=\s*\[\]string\{(.*?)\}`)
	reGoReaderMaps     = regexp.MustCompile(`(?s)readerMaps\s*:?=\s*\[\]string\{(.*?)\}`)
	reGoStringLiteral  = regexp.MustCompile(`"([A-Za-z_][A-Za-z0-9_]*)"`)
)

// EBPFSourceDir returns the directory holding the eBPF C sources, relative to
// the internal/kernel package directory.
func EBPFSourceDir() string {
	return filepath.Join("..", "..", "platform", "linux", "ebpf")
}

// ParseEBPFSources parses every .c file in dir into an EBPFSources.
//
// Map and ring buffer references are attributed to the enclosing program,
// where "enclosing" means the text from one SEC() declaration up to the next.
// Text before the first SEC() is the file prologue: static __always_inline
// helpers such as pid_is_filtered() live there and are reached from every
// program in the file, so prologue references are attributed to all of them.
// Attributing them to nothing would make file_pid_filter look unread.
func ParseEBPFSources(dir string) (*EBPFSources, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("reading ebpf source dir %s: %w", dir, err)
	}

	out := &EBPFSources{
		MapRefs:          make(map[string][]string),
		RingbufProducers: make(map[string][]string),
	}
	refSeen := make(map[string]map[string]bool)
	prodSeen := make(map[string]map[string]bool)

	files := make([]string, 0, len(entries))
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".c") {
			continue
		}
		files = append(files, e.Name())
	}
	sort.Strings(files)
	if len(files) == 0 {
		return nil, fmt.Errorf("no .c files found in %s", dir)
	}

	for _, name := range files {
		raw, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			return nil, fmt.Errorf("reading %s: %w", name, err)
		}
		src := string(raw)

		for _, m := range reEBPFProgram.FindAllStringSubmatchIndex(src, -1) {
			sec := src[m[2]:m[3]]
			progName := ""
			if m[4] >= 0 {
				progName = src[m[4]:m[5]]
			} else if m[6] >= 0 {
				progName = src[m[6]:m[7]]
			}
			if progName == "" {
				continue
			}
			out.Programs = append(out.Programs, EBPFProgram{
				Name:    progName,
				Section: sec,
				File:    name,
				Line:    lineOfOffset(src, m[0]),
			})
		}

		for _, m := range reEBPFMapDef.FindAllStringSubmatchIndex(src, -1) {
			mapName := src[m[2]:m[3]]
			start := structStartBefore(src, m[0])
			decl := src[start:m[1]]
			mapType := ""
			if t := reEBPFMapType.FindStringSubmatch(decl); t != nil {
				mapType = t[1]
			}
			out.Maps = append(out.Maps, EBPFMap{
				Name: mapName,
				Type: mapType,
				File: name,
				Line: lineOfOffset(src, m[0]),
			})
		}

		fileScope, bodies := splitProgramBodies(blankComments(src))
		fileProgs := make([]string, 0, len(bodies))
		for _, b := range bodies {
			fileProgs = append(fileProgs, b.prog)
		}

		record := func(seen map[string]map[string]bool, dst map[string][]string, key string, progs []string) {
			if seen[key] == nil {
				seen[key] = make(map[string]bool)
			}
			for _, p := range progs {
				if seen[key][p] {
					continue
				}
				seen[key][p] = true
				dst[key] = append(dst[key], p)
			}
		}

		scan := func(text string, progs []string) {
			for _, m := range reEBPFMapHelper.FindAllStringSubmatch(text, -1) {
				record(refSeen, out.MapRefs, m[1], progs)
			}
			for _, m := range reEBPFRingbufCall.FindAllStringSubmatch(text, -1) {
				record(refSeen, out.MapRefs, m[1], progs)
				record(prodSeen, out.RingbufProducers, m[1], progs)
			}
		}

		scan(fileScope, fileProgs)
		for _, b := range bodies {
			scan(b.text, []string{b.prog})
		}
	}

	// common.h is parsed last, as shared file scope.
	//
	// It is where the maps and helpers every program needs live: the
	// event_stats and filter_stats accounting maps are declared there once
	// rather than in each of the eight .c files, because libbpf's static
	// linker merges identically-declared maps by name. Parsing only *.c
	// made those maps invisible to every assertion in this file — neither
	// counted as defined nor as read — which is a blind spot that grows
	// with whatever else moves into the header. Header references are
	// attributed to every program in the object, because a static
	// __always_inline helper in common.h is reachable from all of them.
	if err := parseSharedEBPFHeader(dir, out, refSeen, prodSeen); err != nil {
		return nil, err
	}

	for k := range out.MapRefs {
		sort.Strings(out.MapRefs[k])
	}
	for k := range out.RingbufProducers {
		sort.Strings(out.RingbufProducers[k])
	}
	sort.Slice(out.Programs, func(i, j int) bool { return out.Programs[i].Name < out.Programs[j].Name })
	sort.Slice(out.Maps, func(i, j int) bool { return out.Maps[i].Name < out.Maps[j].Name })
	return out, nil
}

// parseSharedEBPFHeader folds common.h into an EBPFSources built from the .c
// files: its map definitions are definitions, and its map references belong to
// every program in the object.
func parseSharedEBPFHeader(dir string, out *EBPFSources,
	refSeen, prodSeen map[string]map[string]bool) error {
	const name = "common.h"
	raw, err := os.ReadFile(filepath.Join(dir, name))
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("reading %s: %w", name, err)
	}
	src := string(raw)

	for _, m := range reEBPFMapDef.FindAllStringSubmatchIndex(src, -1) {
		mapName := src[m[2]:m[3]]
		start := structStartBefore(src, m[0])
		decl := src[start:m[1]]
		mapType := ""
		if t := reEBPFMapType.FindStringSubmatch(decl); t != nil {
			mapType = t[1]
		}
		out.Maps = append(out.Maps, EBPFMap{
			Name: mapName,
			Type: mapType,
			File: name,
			Line: lineOfOffset(src, m[0]),
		})
	}

	allProgs := make([]string, 0, len(out.Programs))
	for _, p := range out.Programs {
		allProgs = append(allProgs, p.Name)
	}

	record := func(seen map[string]map[string]bool, dst map[string][]string, key string) {
		if seen[key] == nil {
			seen[key] = make(map[string]bool)
		}
		for _, prog := range allProgs {
			if seen[key][prog] {
				continue
			}
			seen[key][prog] = true
			dst[key] = append(dst[key], prog)
		}
	}
	refs := blankComments(src)
	for _, m := range reEBPFMapHelper.FindAllStringSubmatch(refs, -1) {
		record(refSeen, out.MapRefs, m[1])
	}
	for _, m := range reEBPFRingbufCall.FindAllStringSubmatch(refs, -1) {
		record(refSeen, out.MapRefs, m[1])
		record(prodSeen, out.RingbufProducers, m[1])
	}
	return nil
}

type programBody struct {
	prog string
	text string
}

// splitProgramBodies cuts src at every SEC() line and separates program bodies
// from file-scope text.
//
// A chunk headed by a program's SEC() is that program's body. Every other
// chunk — the text before the first SEC(), and any chunk headed by a
// SEC(".maps") map definition or SEC("license") — is file scope, because that
// is where the static __always_inline helpers live. pid_is_filtered() is
// declared after the map definitions it consults in every file that has one,
// so treating only the pre-first-SEC text as file scope would make
// net_pid_filter, sec_pid_filter and comm_filter look unread when in fact
// every program in their file reads them through that helper.
//
// Attributing file scope to all programs in the file is the conservative
// direction: it can report a map read that only one program reaches as "read
// by several", which no assertion here depends on, but it cannot invent a read
// where there is none.
func splitProgramBodies(src string) (string, []programBody) {
	cuts := reEBPFSECAny.FindAllStringSubmatchIndex(src, -1)
	if len(cuts) == 0 {
		return src, nil
	}

	progAt := make(map[int]string)
	for _, m := range reEBPFProgram.FindAllStringSubmatchIndex(src, -1) {
		name := ""
		if m[4] >= 0 {
			name = src[m[4]:m[5]]
		} else if m[6] >= 0 {
			name = src[m[6]:m[7]]
		}
		if name != "" {
			progAt[m[0]] = name
		}
	}

	var fileScope strings.Builder
	fileScope.WriteString(src[:cuts[0][0]])

	var bodies []programBody
	for i, c := range cuts {
		end := len(src)
		if i+1 < len(cuts) {
			end = cuts[i+1][0]
		}
		chunk := src[c[0]:end]
		name, ok := progAt[c[0]]
		if !ok {
			fileScope.WriteString(chunk)
			continue
		}
		bodies = append(bodies, programBody{prog: name, text: chunk})
	}
	return fileScope.String(), bodies
}

// blankComments replaces the body of every C comment with spaces, keeping the
// source's length and line breaks so offsets and line numbers still hold.
//
// Reference scanning has to run on this rather than on the raw text. common.h
// documents the pattern it replaced by quoting it:
//
//	evt = bpf_ringbuf_reserve(&events, sizeof(*evt), 0);
//
// and that quotation, in a header included by every file, credited the
// "events" ring buffer with a producer in all 61 programs. A model that reads
// comments as code can be made to assert anything by writing a comment.
func blankComments(src string) string {
	out := []byte(src)
	const (
		code = iota
		line
		block
		str
	)
	state := code
	for i := 0; i < len(out); i++ {
		c := out[i]
		switch state {
		case code:
			switch {
			case c == '/' && i+1 < len(out) && out[i+1] == '/':
				state = line
				out[i], out[i+1] = ' ', ' '
				i++
			case c == '/' && i+1 < len(out) && out[i+1] == '*':
				state = block
				out[i], out[i+1] = ' ', ' '
				i++
			case c == '"':
				state = str
			}
		case line:
			if c == '\n' {
				state = code
				continue
			}
			out[i] = ' '
		case block:
			if c == '*' && i+1 < len(out) && out[i+1] == '/' {
				out[i], out[i+1] = ' ', ' '
				i++
				state = code
				continue
			}
			if c != '\n' {
				out[i] = ' '
			}
		case str:
			if c == '\\' {
				i++
				continue
			}
			if c == '"' {
				state = code
			}
		}
	}
	return string(out)
}

// structStartBefore walks back from a map definition's closing brace to the
// "struct {" that opened it, so the map's __uint(type, ...) is in scope.
func structStartBefore(src string, closeIdx int) int {
	if i := strings.LastIndex(src[:closeIdx], "struct {"); i >= 0 {
		return i
	}
	return 0
}

func lineOfOffset(src string, off int) int {
	if off > len(src) {
		off = len(src)
	}
	return strings.Count(src[:off], "\n") + 1
}

// ParseLoaderModel reads the Linux loader's Go sources and extracts which maps
// userspace writes and which ring buffers it opens readers on.
//
// It is parsed rather than hardcoded so that adding a map write in
// syncPolicyToMaps, or a ring buffer to openReaders, is picked up by the
// consistency tests without anyone remembering to update a list. The three
// extraction points are guarded individually: if a refactor renames any of
// them the model comes back empty and the tests say so instead of passing
// vacuously.
func ParseLoaderModel(kernelDir string) (*LoaderModel, error) {
	// ebpf_attach.go and ebpf_attach_linux.go hold the attach planner and
	// the attach calls; driver_linux.go only calls into them. They are read
	// here so TestEBPFLoaderAttachMechanismsUnchanged sees the whole attach
	// surface in one string — a link.Fentry appearing in any of these files
	// is a change to what the loader can reach and the guard should catch
	// it wherever it lands. ebpf_watchdog_linux.go is included for the same
	// reason: it re-attaches links after a tamper signal.
	wantFiles := []string{
		"driver_linux.go",
		"self_exclude_linux.go",
		"ebpf_watchdog_linux.go",
		"ebpf_attach.go",
		"ebpf_attach_linux.go",
	}
	var sb strings.Builder
	for _, f := range wantFiles {
		raw, err := os.ReadFile(filepath.Join(kernelDir, f))
		if err != nil {
			return nil, fmt.Errorf("reading loader source %s: %w", f, err)
		}
		sb.Write(raw)
		sb.WriteString("\n")
	}
	src := sb.String()

	writes := make(map[string]bool)
	for _, m := range reGoCollMapLiteral.FindAllStringSubmatch(src, -1) {
		writes[m[1]] = true
	}
	if g := reGoSelfFilterMaps.FindStringSubmatch(src); g != nil {
		for _, m := range reGoStringLiteral.FindAllStringSubmatch(g[1], -1) {
			writes[m[1]] = true
		}
	}

	readers := make(map[string]bool)
	if g := reGoReaderMaps.FindStringSubmatch(src); g != nil {
		for _, m := range reGoStringLiteral.FindAllStringSubmatch(g[1], -1) {
			readers[m[1]] = true
		}
	}

	// openReaders() indexes coll.Maps by a loop variable, so every ring
	// buffer name also shows up as a literal in readerMaps. Those are
	// reads, not writes; drop them from the write set so a ring buffer is
	// not reported as a map userspace puts entries into.
	for name := range readers {
		delete(writes, name)
	}

	return &LoaderModel{
		WrittenMaps:    sortedKeys(writes),
		ReaderRingbufs: sortedKeys(readers),
		Source:         src,
	}, nil
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// LoaderAttachesProgram reports whether the loader makes an attach call for
// prog, plus the name of the attach call it makes.
//
// This used to be a hand-written model of attachTracepoints and
// attachLSMPrograms, which keyed off Go symbol prefixes, and it could drift
// from the loader it modelled. It no longer models anything: it calls
// ebpfAttachDecision, the same function attachPrograms calls, over the SEC()
// string parsed out of the C. Loader and test cannot disagree about which
// programs get an attach call, because there is only one answer and both read
// it from the same place.
//
// "Makes an attach call" is still not "is attached": the kernel can refuse,
// and that is a runtime fact these static tests cannot see. The capability
// report covers it, from d.attachMisses.
func LoaderAttachesProgram(prog EBPFProgram) (bool, string) {
	target, attempt, _ := ebpfAttachDecision(prog.Name, prog.Section)
	if !attempt {
		return false, ""
	}
	switch target.Kind {
	case ebpfAttachTracepoint:
		return true, "link.Tracepoint"
	case ebpfAttachKprobe:
		return true, "link.Kprobe"
	case ebpfAttachKretprobe:
		return true, "link.Kretprobe"
	case ebpfAttachLSM:
		return true, "link.AttachLSM"
	}
	return false, ""
}

// EBPFProgramNames returns the parsed program names, sorted.
func (s *EBPFSources) EBPFProgramNames() []string {
	out := make([]string, 0, len(s.Programs))
	for _, p := range s.Programs {
		out = append(out, p.Name)
	}
	sort.Strings(out)
	return out
}

// AttachedPrograms splits the parsed programs into those the loader attaches
// and those it does not.
func (s *EBPFSources) AttachedPrograms() (attached, unattached []EBPFProgram) {
	for _, p := range s.Programs {
		if ok, _ := LoaderAttachesProgram(p); ok {
			attached = append(attached, p)
			continue
		}
		unattached = append(unattached, p)
	}
	return attached, unattached
}

// MapByName returns the definition of the named map, if the sources define one.
func (s *EBPFSources) MapByName(name string) (EBPFMap, bool) {
	for _, m := range s.Maps {
		if m.Name == name {
			return m, true
		}
	}
	return EBPFMap{}, false
}
