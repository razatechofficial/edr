//go:build windows

package main

import (
	"sync"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	modkernel32            = windows.NewLazySystemDLL("kernel32.dll")
	procGlobalMemoryStatus = modkernel32.NewProc("GlobalMemoryStatusEx")
	procGetSystemTimes     = modkernel32.NewProc("GetSystemTimes")
	cpuMu                  sync.Mutex
	lastIdle               uint64
	lastKernel             uint64
	lastUser               uint64
)

type memoryStatusEx struct {
	Length               uint32
	MemoryLoad           uint32
	TotalPhys            uint64
	AvailPhys            uint64
	TotalPageFile        uint64
	AvailPageFile        uint64
	TotalVirtual         uint64
	AvailVirtual         uint64
	AvailExtendedVirtual uint64
}

func sampleSystem() (cpuPct float64, memUsed, memTotal uint64) {
	var mem memoryStatusEx
	mem.Length = uint32(unsafe.Sizeof(mem))
	r, _, _ := procGlobalMemoryStatus.Call(uintptr(unsafe.Pointer(&mem)))
	if r != 0 {
		memTotal = mem.TotalPhys
		if mem.TotalPhys > mem.AvailPhys {
			memUsed = mem.TotalPhys - mem.AvailPhys
		}
	}

	idle, kernel, user, ok := readTimes()
	if !ok {
		return cpuPct, memUsed, memTotal
	}
	cpuMu.Lock()
	defer cpuMu.Unlock()
	if lastKernel > 0 {
		di := idle - lastIdle
		dk := kernel - lastKernel
		du := user - lastUser
		sys := dk + du
		if sys > 0 {
			cpuPct = (1 - float64(di)/float64(sys)) * 100
			if cpuPct < 0 {
				cpuPct = 0
			}
		}
	} else {
		time.Sleep(120 * time.Millisecond)
		idle2, kernel2, user2, ok2 := readTimes()
		if ok2 {
			di := idle2 - idle
			sys := (kernel2 - kernel) + (user2 - user)
			if sys > 0 {
				cpuPct = (1 - float64(di)/float64(sys)) * 100
			}
		}
	}
	lastIdle, lastKernel, lastUser = idle, kernel, user
	return cpuPct, memUsed, memTotal
}

func readTimes() (idle, kernel, user uint64, ok bool) {
	var i, k, u windows.Filetime
	r, _, _ := procGetSystemTimes.Call(
		uintptr(unsafe.Pointer(&i)),
		uintptr(unsafe.Pointer(&k)),
		uintptr(unsafe.Pointer(&u)),
	)
	if r == 0 {
		return 0, 0, 0, false
	}
	return filetimeToUint64(i), filetimeToUint64(k), filetimeToUint64(u), true
}

func filetimeToUint64(ft windows.Filetime) uint64 {
	return (uint64(ft.HighDateTime) << 32) | uint64(ft.LowDateTime)
}
