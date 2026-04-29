//go:build linux

package collector

import (
	"os"
	"strconv"
	"strings"
)

// EnrichFromProcLinux reads the Linux-only fields (cgroup, container id,
// container runtime) for pid out of /proc and merges them into the tracker.
// It is safe to call repeatedly; merges are idempotent and bounded.
func (t *LineageTracker) EnrichFromProcLinux(pid uint32) {
	if t == nil || pid == 0 {
		return
	}
	cg := readProcCgroup(pid)
	if cg == "" {
		return
	}
	id, runtime := ParseContainerFromCgroup(cg)
	t.Upsert(LineageEntry{
		PID:              pid,
		Cgroup:           cg,
		ContainerID:      id,
		ContainerRuntime: runtime,
	})
}

func readProcCgroup(pid uint32) string {
	data, err := os.ReadFile("/proc/" + strconv.FormatUint(uint64(pid), 10) + "/cgroup")
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}
