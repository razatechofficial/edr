//go:build darwin

package main

/*
#include <stdint.h>
#include <mach/mach.h>
#include <mach/mach_host.h>

static int edrCPUTicks(uint64_t *idle, uint64_t *total) {
	host_cpu_load_info_data_t info;
	mach_msg_type_number_t count = HOST_CPU_LOAD_INFO_COUNT;
	kern_return_t kr = host_statistics(mach_host_self(), HOST_CPU_LOAD_INFO, (host_info_t)&info, &count);
	if (kr != KERN_SUCCESS) {
		return -1;
	}
	uint64_t t = 0;
	for (int i = 0; i < CPU_STATE_MAX; i++) {
		t += info.cpu_ticks[i];
	}
	*idle = info.cpu_ticks[CPU_STATE_IDLE];
	*total = t;
	return 0;
}
*/
import "C"

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
	free := sysctlPages("vm.page_free_count")
	inactive := sysctlPages("vm.page_inactive_count")
	speculative := sysctlPages("vm.page_speculative_count")
	purgeable := sysctlPages("vm.page_purgeable_count")
	avail := (free + inactive + speculative + purgeable) * page
	if memTotal > avail {
		memUsed = memTotal - avail
	}

	idle, total := readCPUTicks()
	cpuMu.Lock()
	defer cpuMu.Unlock()
	if lastTotal > 0 && total > lastTotal {
		cpuPct = busyCPU(lastIdle, lastTotal, idle, total)
		lastIdle, lastTotal = idle, total
		return cpuPct, memUsed, memTotal
	}
	time.Sleep(120 * time.Millisecond)
	idle2, total2 := readCPUTicks()
	cpuPct = busyCPU(idle, total, idle2, total2)
	if total2 > 0 {
		lastIdle, lastTotal = idle2, total2
	} else {
		lastIdle, lastTotal = idle, total
	}
	return cpuPct, memUsed, memTotal
}

func readCPUTicks() (idle, total uint64) {
	var i, t C.uint64_t
	if C.edrCPUTicks(&i, &t) != 0 {
		return 0, 0
	}
	return uint64(i), uint64(t)
}

func sysctlPages(name string) uint64 {
	b, err := unix.SysctlRaw(name)
	if err != nil || len(b) == 0 {
		return 0
	}
	switch len(b) {
	case 4:
		return uint64(binary.LittleEndian.Uint32(b))
	case 8:
		return binary.LittleEndian.Uint64(b)
	default:
		if len(b) >= 4 {
			return uint64(binary.LittleEndian.Uint32(b[:4]))
		}
	}
	return 0
}
