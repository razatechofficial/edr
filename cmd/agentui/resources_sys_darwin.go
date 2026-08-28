//go:build darwin

package main

import (
	"encoding/binary"
	"sync"
	"time"

	"golang.org/x/sys/unix"
)

var (
	cpuMu     sync.Mutex
	lastIdle  uint64
	lastTotal uint64
)

func sampleSystem() (cpuPct float64, memUsed, memTotal uint64) {
	if n, err := unix.SysctlUint64("hw.memsize"); err == nil {
		memTotal = n
	}
	page := uint64(unix.Getpagesize())
	free, ferr := unix.SysctlUint64("vm.page_free_count")
	inactive, ierr := unix.SysctlUint64("vm.page_inactive_count")
	if ferr == nil || ierr == nil {
		avail := (free + inactive) * page
		if memTotal > avail {
			memUsed = memTotal - avail
		}
	}

	idle, total := readCPUTicks()
	cpuMu.Lock()
	defer cpuMu.Unlock()
	if lastTotal > 0 && total > lastTotal {
		didle := idle - lastIdle
		dtotal := total - lastTotal
		if dtotal > 0 {
			cpuPct = (1 - float64(didle)/float64(dtotal)) * 100
			if cpuPct < 0 {
				cpuPct = 0
			}
		}
	} else {
		time.Sleep(120 * time.Millisecond)
		idle2, total2 := readCPUTicks()
		if total2 > total {
			cpuPct = (1 - float64(idle2-idle)/float64(total2-total)) * 100
			if cpuPct < 0 {
				cpuPct = 0
			}
		}
	}
	lastIdle, lastTotal = idle, total
	return cpuPct, memUsed, memTotal
}

func readCPUTicks() (idle, total uint64) {
	b, err := unix.SysctlRaw("kern.cp_time")
	if err != nil || len(b) < 20 {
		return 0, 0
	}
	width := 8
	if len(b) == 20 {
		width = 4
	}
	n := len(b) / width
	if n > 5 {
		n = 5
	}
	var vals [5]uint64
	for i := 0; i < n; i++ {
		off := i * width
		if width == 8 {
			vals[i] = binary.LittleEndian.Uint64(b[off : off+8])
		} else {
			vals[i] = uint64(binary.LittleEndian.Uint32(b[off : off+4]))
		}
		total += vals[i]
	}
	// USER NICE SYS IDLE INTR — idle is index 3
	idle = vals[3]
	return idle, total
}
