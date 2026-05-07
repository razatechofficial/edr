//go:build !linux

package collector

import "os"

// fileTailIdentity returns device/inode when the platform exposes them in FileInfo.Sys().
// Non-Unix platforms return zeros and log tail uses path+size heuristics only.
func fileTailIdentity(fi os.FileInfo) (dev, ino uint64) {
	_ = fi
	return 0, 0
}
