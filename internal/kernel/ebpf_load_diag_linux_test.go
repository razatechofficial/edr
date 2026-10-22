//go:build linux && integration

package kernel

// TEMPORARY DIAGNOSTIC — delete once the verifier rejections are fixed.
//
// The Monitoring Proof Linux lane is green and proves nothing: every subtest
// skips with "MISSING PREREQUISITE: eBPF driver failed to start", because the
// object does not load on the hosted runner's kernel at all. The collection
// load aborts on the first rejected program, so one run names one program.
// This loads each program on its own, against the full map set, and prints the
// complete verifier log for every one the kernel refuses.

import (
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"
	"testing"

	"github.com/cilium/ebpf"
)

func TestLinuxEBPFPerProgramLoadDiagnostic(t *testing.T) {
	if euid := os.Geteuid(); euid != 0 {
		t.Skipf("MISSING PREREQUISITE: root (euid=%d)", euid)
	}
	objPath, tried := resolveBPFObjectForTest()
	if objPath == "" {
		t.Skipf("MISSING PREREQUISITE: compiled BPF object. Tried: %s", strings.Join(tried, ", "))
	}
	spec, err := ebpf.LoadCollectionSpec(objPath)
	if err != nil {
		t.Fatalf("loading collection spec from %s: %v", objPath, err)
	}

	names := make([]string, 0, len(spec.Programs))
	for n := range spec.Programs {
		names = append(names, n)
	}
	sort.Strings(names)
	t.Logf("object %s: %d programs, %d maps", objPath, len(spec.Programs), len(spec.Maps))

	var bad []string
	for _, name := range names {
		sub := &ebpf.CollectionSpec{
			Maps:      spec.Maps,
			Programs:  map[string]*ebpf.ProgramSpec{name: spec.Programs[name]},
			Types:     spec.Types,
			ByteOrder: spec.ByteOrder,
		}
		coll, err := ebpf.NewCollectionWithOptions(sub, ebpf.CollectionOptions{
			Programs: ebpf.ProgramOptions{LogLevel: ebpf.LogLevelBranch},
		})
		if err == nil {
			coll.Close()
			continue
		}
		bad = append(bad, name)
		// %+v on the wrapping error does not reach the VerifierError
		// inside it, and VerifierError.Error() omits the instruction
		// trace. Unwrap first.
		detail := err.Error()
		var ve *ebpf.VerifierError
		if errors.As(err, &ve) {
			detail = fmt.Sprintf("%+v", ve)
		}
		t.Logf("=== REJECTED %s (SEC %q)\n%s\n=== END %s",
			name, spec.Programs[name].SectionName, detail, name)
	}
	t.Logf("=== %d of %d programs rejected: %s", len(bad), len(names), strings.Join(bad, ", "))
}
