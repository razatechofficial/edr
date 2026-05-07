//go:build linux

package collector

import (
	"os"
	"syscall"
)

// fileTailIdentity returns st_dev/st_ino for rotation detection (log tail offsets).
func fileTailIdentity(fi os.FileInfo) (dev, ino uint64) {
	if fi == nil {
		return 0, 0
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok || st == nil {
		return 0, 0
	}
	return uint64(st.Dev), uint64(st.Ino)
}
