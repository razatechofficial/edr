//go:build linux

package collector

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"time"

	"golang.org/x/sys/unix"
)

func readMountinfoFingerprint() (string, error) {
	b, err := os.ReadFile("/proc/self/mountinfo")
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:]), nil
}

// runMountTableWatch periodically re-applies fanotify marks when /proc/self/mountinfo
// changes (remounts, new mounts) so notifications keep covering configured mount points.
func (f *FanotifySource) runMountTableWatch(ctx context.Context) {
	t := time.NewTicker(30 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			_ = f.refreshFanotifyMarksIfMountTableChanged()
		}
	}
}

func (f *FanotifySource) refreshFanotifyMarksIfMountTableChanged() error {
	fp, err := readMountinfoFingerprint()
	if err != nil {
		return err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if !f.started || f.fd < 0 {
		return nil
	}
	if fp == f.lastMountFP {
		return nil
	}
	mask := uint64(unix.FAN_MODIFY | unix.FAN_CLOSE_WRITE | unix.FAN_OPEN_EXEC)
	fd := f.fd
	for _, m := range f.mounts {
		_ = unix.FanotifyMark(fd, unix.FAN_MARK_REMOVE|unix.FAN_MARK_MOUNT, mask, unix.AT_FDCWD, m)
	}
	for _, m := range f.mounts {
		if err := unix.FanotifyMark(fd, unix.FAN_MARK_ADD|unix.FAN_MARK_MOUNT, mask, unix.AT_FDCWD, m); err != nil {
			if err == unix.ENOENT {
				continue
			}
			f.recordError(err)
			return err
		}
	}
	f.lastMountFP = fp
	return nil
}
