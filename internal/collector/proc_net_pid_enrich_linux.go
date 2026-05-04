//go:build linux

package collector

import (
	"context"
	"os"
	"strconv"
	"strings"
)

// buildSocketInodeToPIDMap walks /proc/<pid>/fd/* and maps socket inode numbers
// to owning PIDs. Shared by SocketSource snapshots and NetworkCollector
// linux_proc_net_pid_enrich path.
func buildSocketInodeToPIDMap(ctx context.Context, onReadProcErr func(error)) map[uint64]uint32 {
	out := make(map[uint64]uint32, 256)
	procEntries, err := os.ReadDir("/proc")
	if err != nil {
		if onReadProcErr != nil {
			onReadProcErr(err)
		}
		return out
	}
	for _, pe := range procEntries {
		if ctx.Err() != nil {
			return out
		}
		if !pe.IsDir() {
			continue
		}
		pid64, err := strconv.ParseUint(pe.Name(), 10, 32)
		if err != nil {
			continue
		}
		pid := uint32(pid64)
		fdDir := "/proc/" + pe.Name() + "/fd"
		fdEntries, err := os.ReadDir(fdDir)
		if err != nil {
			continue
		}
		for _, fe := range fdEntries {
			target, err := os.Readlink(fdDir + "/" + fe.Name())
			if err != nil {
				continue
			}
			if !strings.HasPrefix(target, "socket:[") {
				continue
			}
			closeIdx := strings.IndexByte(target, ']')
			if closeIdx < 0 {
				continue
			}
			inode, perr := strconv.ParseUint(target[len("socket:["):closeIdx], 10, 64)
			if perr != nil {
				continue
			}
			out[inode] = pid
		}
	}
	return out
}
