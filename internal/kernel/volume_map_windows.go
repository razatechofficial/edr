//go:build windows

package kernel

import (
	"strings"
	"sync"
	"unsafe"

	"golang.org/x/sys/windows"
)

// volumeMap caches \Device\HarddiskVolumeN -> "C:" style mappings so that
// file paths emitted by ETW Kernel-File (which uses NT device paths) can be
// rewritten to drive-letter form before downstream consumers see them.
//
// Refresh policy: full repopulation on construction and after any caller
// invokes Refresh() — e.g. on volume mount/unmount events. Reads are
// lock-free under sync.RWMutex.RLock.
type volumeMap struct {
	mu      sync.RWMutex
	entries map[string]string
}

func newVolumeMap() *volumeMap {
	v := &volumeMap{entries: make(map[string]string)}
	v.Refresh()
	return v
}

// Refresh walks every logical drive on the host and resolves each to its
// underlying NT device name via QueryDosDeviceW. Errors are best-effort —
// drives we cannot resolve remain unmapped and the corresponding paths
// pass through normalize() unchanged.
func (v *volumeMap) Refresh() {
	logical, err := getLogicalDriveStrings()
	if err != nil {
		return
	}
	next := make(map[string]string, len(logical))
	for _, drive := range logical {
		// Strip trailing backslash. "C:\" -> "C:".
		drv := strings.TrimRight(drive, `\`)
		device, err := queryDosDevice(drv)
		if err != nil || device == "" {
			continue
		}
		next[device] = drv
	}
	v.mu.Lock()
	v.entries = next
	v.mu.Unlock()
}

// Normalize rewrites NT device paths (e.g. \Device\HarddiskVolume3\Users\)
// into drive-letter form (C:\Users\). Paths that do not start with a known
// device prefix are returned unchanged.
func (v *volumeMap) Normalize(path string) string {
	if path == "" {
		return path
	}
	if !strings.HasPrefix(path, `\Device\`) {
		return path
	}
	v.mu.RLock()
	defer v.mu.RUnlock()
	for device, drive := range v.entries {
		if strings.HasPrefix(path, device) {
			rest := path[len(device):]
			if rest == "" {
				return drive
			}
			if rest[0] != '\\' {
				rest = `\` + rest
			}
			return drive + rest
		}
	}
	return path
}

func getLogicalDriveStrings() ([]string, error) {
	const bufLen = 1024
	buf := make([]uint16, bufLen)
	n, err := windows.GetLogicalDriveStrings(uint32(len(buf)-1), &buf[0])
	if err != nil {
		return nil, err
	}
	if n == 0 {
		return nil, nil
	}
	if n > uint32(len(buf)-1) {
		// Reallocate exactly the size the OS asked for.
		buf = make([]uint16, n+1)
		n, err = windows.GetLogicalDriveStrings(uint32(len(buf)-1), &buf[0])
		if err != nil {
			return nil, err
		}
	}
	// GetLogicalDriveStrings writes a sequence of NUL-terminated strings
	// followed by a final NUL ("C:\\\x00D:\\\x00\x00").
	var out []string
	start := 0
	for i := 0; i < int(n); i++ {
		if buf[i] == 0 {
			if i > start {
				out = append(out, windows.UTF16ToString(buf[start:i]))
			}
			start = i + 1
		}
	}
	return out, nil
}

func queryDosDevice(name string) (string, error) {
	namePtr, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return "", err
	}
	const initBuf = 256
	buf := make([]uint16, initBuf)
	for attempt := 0; attempt < 3; attempt++ {
		n, err := windows.QueryDosDevice(namePtr, &buf[0], uint32(len(buf)))
		if err == nil && n > 0 {
			// Return only the first device target (multiple NUL-terminated
			// entries can follow but we only care about the canonical one).
			return windows.UTF16ToString(buf), nil
		}
		// Grow buffer and retry on ERROR_INSUFFICIENT_BUFFER.
		buf = make([]uint16, len(buf)*4)
	}
	_ = unsafe.Sizeof(uint16(0))
	return "", nil
}
