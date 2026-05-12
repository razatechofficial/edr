//go:build linux

package kernel

import (
	"strings"
	"testing"
)

// TestProcessEventArgsSpaceSeparated documents the wire contract between the
// eBPF execve handler (capture_argv in platform/linux/ebpf/process_monitor.c)
// and the Go decoder: argv tokens arrive in a single null-terminated buffer
// separated by single ASCII spaces, with ArgsSize giving the number of bytes
// used (excluding the trailing NUL). The Go side is therefore expected to
// surface the full command line just by reading bytes [0:ArgsSize].
func TestProcessEventArgsSpaceSeparated(t *testing.T) {
	const cmdline = "/bin/sh -c echo hi"
	var evt bpfProcessEvent
	copy(evt.Args[:], cmdline)
	evt.ArgsSize = uint32(len(cmdline))
	got := nullTerminated(evt.Args[:min(int(evt.ArgsSize), bpfArgsLen)])
	if got != cmdline {
		t.Fatalf("argv roundtrip: got %q want %q", got, cmdline)
	}
	parts := strings.Split(got, " ")
	if len(parts) != 4 {
		t.Fatalf("expected 4 argv tokens, got %d: %v", len(parts), parts)
	}
	if parts[0] != "/bin/sh" || parts[1] != "-c" || parts[2] != "echo" || parts[3] != "hi" {
		t.Fatalf("argv contents: %v", parts)
	}
}

// TestProcessEventArgsTruncation ensures the Go side caps at bpfArgsLen even
// when the kernel wrote a larger ArgsSize (defense in depth).
func TestProcessEventArgsTruncation(t *testing.T) {
	var evt bpfProcessEvent
	for i := range evt.Args {
		evt.Args[i] = 'a'
	}
	evt.ArgsSize = uint32(len(evt.Args)) * 2
	got := nullTerminated(evt.Args[:min(int(evt.ArgsSize), bpfArgsLen)])
	if len(got) != len(evt.Args) {
		t.Fatalf("truncation failed: len=%d want %d", len(got), len(evt.Args))
	}
}
