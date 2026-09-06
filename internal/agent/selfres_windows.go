//go:build windows

package agent

import (
	"sync"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	selfCPUMu       sync.Mutex
	selfCPUAt       time.Time
	selfCPUTicks    uint64
	procSelfMemInfo = windows.NewLazySystemDLL("kernel32.dll").NewProc("K32GetProcessMemoryInfo")
)

type selfMemCounters struct {
	CB                         uint32
	PageFaultCount             uint32
	PeakWorkingSetSize         uintptr
	WorkingSetSize             uintptr
	QuotaPeakPagedPoolUsage    uintptr
	QuotaPagedPoolUsage        uintptr
	QuotaPeakNonPagedPoolUsage uintptr
	QuotaNonPagedPoolUsage     uintptr
	PagefileUsage              uintptr
	PeakPagefileUsage          uintptr
}

func sampleSelfResources() (cpu, memMB float64) {
	h := windows.CurrentProcess()
	var pmc selfMemCounters
	pmc.CB = uint32(unsafe.Sizeof(pmc))
	r, _, _ := procSelfMemInfo.Call(uintptr(h), uintptr(unsafe.Pointer(&pmc)), uintptr(pmc.CB))
	if r != 0 {
		memMB = float64(pmc.WorkingSetSize) / (1024 * 1024)
	}

	var create, exit, kernel, user windows.Filetime
	if err := windows.GetProcessTimes(h, &create, &exit, &kernel, &user); err != nil {
		return cpu, memMB
	}
	ticks := (uint64(kernel.HighDateTime)<<32 | uint64(kernel.LowDateTime)) +
		(uint64(user.HighDateTime)<<32 | uint64(user.LowDateTime))
	now := time.Now()
	selfCPUMu.Lock()
	defer selfCPUMu.Unlock()
	if !selfCPUAt.IsZero() && ticks >= selfCPUTicks {
		wall := now.Sub(selfCPUAt).Seconds()
		if wall > 0.2 {
			delta := float64(ticks-selfCPUTicks) / 1e7
			n := float64(windows.GetActiveProcessorCount(0xFFFF))
			if n < 1 {
				n = 1
			}
			cpu = (delta / wall / n) * 100
			if cpu < 0 {
				cpu = 0
			}
			if cpu > 100 {
				cpu = 100
			}
		}
	}
	selfCPUAt = now
	selfCPUTicks = ticks
	return cpu, memMB
}
