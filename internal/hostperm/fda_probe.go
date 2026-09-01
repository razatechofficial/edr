package hostperm

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// RunFDAProbe is the process entry point for `fda-probe`. Exit 0 means this
// process can open a Full Disk Access path. A sidecar file lets the console
// observe the result when the probe is launched through Launch Services.
func RunFDAProbe() int {
	ok := ProcessHasFDA()
	writeFDAProbeResult(ok)
	if ok {
		return 0
	}
	return 1
}

func fdaProbeResultPath() string {
	return filepath.Join(os.TempDir(), "com.razatech.edr.fda-probe."+strconv.Itoa(os.Getuid()))
}

func writeFDAProbeResult(ok bool) {
	body := "no\n"
	if ok {
		body = "ok\n"
	}
	_ = os.WriteFile(fdaProbeResultPath(), []byte(body), 0o600)
}

func readFDAProbeResult() bool {
	b, err := os.ReadFile(fdaProbeResultPath())
	if err != nil {
		return false
	}
	return strings.TrimSpace(string(b)) == "ok"
}

func clearFDAProbeResult() {
	_ = os.Remove(fdaProbeResultPath())
}
