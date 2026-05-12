//go:build linux

package collector

import (
	"encoding/binary"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"

	"golang.org/x/sys/unix"
)

// fanotify event info types (include/uapi/linux/fanotify.h).
const (
	fanEventInfoTypeFID  = 1
	fanEventInfoTypeDFID = 2
)

const fanHandleFIDFlag = 0

var (
	openByHandleAtFn = unix.OpenByHandleAt
	nameToHandleAtFn = unix.NameToHandleAt
	readlinkFn       = os.Readlink
)

type mountFIDEntry struct {
	fd   int
	path string
}

// mountFIDCache is a small LRU of fsid -> mount root fd (O_PATH) for open_by_handle_at.
type mountFIDCache struct {
	mu     sync.Mutex
	max    int
	lru    map[string]mountFIDEntry
	order  []string
}

func newMountFIDCache(max int) *mountFIDCache {
	if max <= 0 {
		max = 32
	}
	return &mountFIDCache{max: max, lru: make(map[string]mountFIDEntry)}
}

func (c *mountFIDCache) closeAll() {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, e := range c.lru {
		if e.fd >= 0 {
			_ = unix.Close(e.fd)
		}
	}
	c.lru = make(map[string]mountFIDEntry)
	c.order = c.order[:0]
}

func (c *mountFIDCache) touchLocked(key string) {
	for i, k := range c.order {
		if k == key {
			c.order = append(c.order[:i], c.order[i+1:]...)
			break
		}
	}
	c.order = append(c.order, key)
	if len(c.order) > c.max {
		evict := c.order[0]
		c.order = c.order[1:]
		if e, ok := c.lru[evict]; ok {
			_ = unix.Close(e.fd)
			delete(c.lru, evict)
		}
	}
}

func (c *mountFIDCache) get(key string) (int, bool) {
	if c == nil {
		return -1, false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if e, ok := c.lru[key]; ok {
		c.touchLocked(key)
		return e.fd, true
	}
	return -1, false
}

func (c *mountFIDCache) put(key string, fd int, path string) {
	if c == nil || fd < 0 {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if old, ok := c.lru[key]; ok {
		_ = unix.Close(old.fd)
	}
	c.lru[key] = mountFIDEntry{fd: fd, path: path}
	c.touchLocked(key)
	for len(c.lru) > c.max {
		evict := c.order[0]
		c.order = c.order[1:]
		if e, ok := c.lru[evict]; ok {
			_ = unix.Close(e.fd)
			delete(c.lru, evict)
		}
	}
}

func fsidKey(fsid []byte) string {
	if len(fsid) != 8 {
		return ""
	}
	return string(fsid)
}

// resolveFanotifyFIDPath parses FID info records in a single fanotify event buffer and
// resolves the path via open_by_handle_at. Returns "" on failure.
func (f *FanotifySource) resolveFanotifyFIDPath(event []byte) string {
	if f == nil || len(event) < 24 || f.mountFID == nil {
		return ""
	}
	eventLen := int(binary.LittleEndian.Uint32(event[0:4]))
	if eventLen > len(event) || eventLen < 24 {
		return ""
	}
	ev := event[:eventLen]
	off := 24
	for off+4 <= eventLen {
		infoType := ev[off]
		infoLen := int(binary.LittleEndian.Uint16(ev[off+2 : off+4]))
		if infoLen < 12 || off+infoLen > eventLen {
			break
		}
		if infoType == fanEventInfoTypeFID || infoType == fanEventInfoTypeDFID {
			body := ev[off+4 : off+infoLen]
			if len(body) < 8+8 {
				off += infoLen
				continue
			}
			fsid := body[0:8]
			fhBody := body[8:]
			if len(fhBody) < 8 {
				off += infoLen
				continue
			}
			hb := binary.LittleEndian.Uint32(fhBody[0:4])
			ht := int32(binary.LittleEndian.Uint32(fhBody[4:8]))
			if hb == 0 || int(hb)+8 > len(fhBody) {
				off += infoLen
				continue
			}
			handle := unix.NewFileHandle(ht, fhBody[8:8+hb])
			path, err := f.openPathByHandle(fsid, handle)
			if err == nil && path != "" {
				return path
			}
		}
		off += infoLen
	}
	return ""
}

func (f *FanotifySource) openPathByHandle(fsid []byte, handle unix.FileHandle) (string, error) {
	mfd, err := f.mountFDForFSID(fsid)
	if err != nil || mfd < 0 {
		return "", err
	}
	hfd, err := openByHandleAtFn(mfd, handle, unix.O_PATH)
	if err != nil {
		// Best-effort fallback for kernels/filesystems that deny handle-open:
		// try NameToHandleAt probe and then surface mount-root path.
		if err == unix.EINVAL || err == unix.EPERM || err == unix.ESTALE {
			if mp, merr := f.mountRootPathByFID(fsid); merr == nil && mp != "" {
				if _, _, herr := nameToHandleAtFn(unix.AT_FDCWD, mp, fanHandleFIDFlag); herr == nil {
					f.fidResolveByName.Add(1)
				}
				return mp, nil
			}
			return readlinkFn("/proc/self/fd/" + strconv.Itoa(mfd))
		}
		return "", err
	}
	defer unix.Close(hfd)
	proc := "/proc/self/fd/" + strconv.Itoa(hfd)
	return readlinkFn(proc)
}

func (f *FanotifySource) mountRootPathByFID(fsid []byte) (string, error) {
	key := fsidKey(fsid)
	if key == "" {
		return "", fmt.Errorf("bad fsid")
	}
	if f.mountFID != nil {
		f.mountFID.mu.Lock()
		if e, ok := f.mountFID.lru[key]; ok && e.path != "" {
			f.mountFID.touchLocked(key)
			path := e.path
			f.mountFID.mu.Unlock()
			return path, nil
		}
		f.mountFID.mu.Unlock()
	}
	return findMountPointForFSID(fsid)
}

func (f *FanotifySource) mountFDForFSID(fsid []byte) (int, error) {
	key := fsidKey(fsid)
	if key == "" {
		return -1, fmt.Errorf("bad fsid")
	}
	if fd, ok := f.mountFID.get(key); ok {
		return fd, nil
	}
	mp, err := findMountPointForFSID(fsid)
	if err != nil || mp == "" {
		return -1, err
	}
	// P2-16: O_CLOEXEC prevents this mount-point fd from leaking into
	// any forked child (e.g. user-triggered remediation actions).
	fd, err := unix.Open(mp, unix.O_RDONLY|unix.O_PATH|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, err
	}
	f.mountFID.put(key, fd, mp)
	return fd, nil
}

func findMountPointForFSID(want []byte) (string, error) {
	if len(want) != 8 {
		return "", fmt.Errorf("fsid len")
	}
	var w32 [2]int32
	w32[0] = int32(binary.LittleEndian.Uint32(want[0:4]))
	w32[1] = int32(binary.LittleEndian.Uint32(want[4:8]))
	data, err := os.ReadFile("/proc/self/mountinfo")
	if err != nil {
		return "", err
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		sep := strings.Index(line, " - ")
		if sep < 0 {
			continue
		}
		prefix := line[:sep]
		fields := strings.Fields(prefix)
		if len(fields) < 5 {
			continue
		}
		mp := unescapeMountinfoPath(fields[4])
		if mp == "" {
			continue
		}
		var st unix.Statfs_t
		if err := unix.Statfs(mp, &st); err != nil {
			continue
		}
		if st.Fsid.Val[0] == w32[0] && st.Fsid.Val[1] == w32[1] {
			return mp, nil
		}
	}
	return "", fmt.Errorf("no mount for fsid")
}

func unescapeMountinfoPath(s string) string {
	s = strings.ReplaceAll(s, `\040`, " ")
	s = strings.ReplaceAll(s, `\011`, "\t")
	s = strings.ReplaceAll(s, `\012`, "\n")
	s = strings.ReplaceAll(s, `\\`, `\`)
	return s
}
