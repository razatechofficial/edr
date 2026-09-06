//go:build windows

package main

import (
	"os/exec"
	"strings"
	"sync"
	"time"
	"unsafe"

	"github.com/razatechofficial/edr/internal/hostperm"
	"golang.org/x/sys/windows"
)

const processQueryLimitedInformation = 0x1000

var (
	modkernel32                 = windows.NewLazySystemDLL("kernel32.dll")
	procK32GetProcessMemoryInfo = modkernel32.NewProc("K32GetProcessMemoryInfo")
)

type processMemoryCounters struct {
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

var (
	cpuMu        sync.Mutex
	lastCPUAt    time.Time
	lastCPUTicks uint64
)

// sampleAgentProcess reports edr-agent.exe (the EDRAgent service), never the UI.
// CPU is a Task Manager-style share of the machine (0-100). Memory is working set.
func sampleAgentProcess() (cpu, memMB float64, uptime string, ok bool) {
	pids := edrAgentPIDs()
	if len(pids) == 0 {
		if mem, found := tasklistAgentMemMB(); found {
			return 0, mem, "", true
		}
		return 0, 0, "", false
	}

	var wsBytes uint64
	var ticks uint64
	var created windows.Filetime
	haveCreate := false
	opened := 0
	for _, pid := range pids {
		h, err := windows.OpenProcess(processQueryLimitedInformation, false, pid)
		if err != nil {
			continue
		}
		opened++
		if pmc, err := processWorkingSet(h); err == nil {
			wsBytes += uint64(pmc.WorkingSetSize)
		}
		if t := processCPUTicks(h); t > 0 {
			ticks += t
		}
		var exit, kernel, user windows.Filetime
		if err := windows.GetProcessTimes(h, &created, &exit, &kernel, &user); err == nil {
			haveCreate = true
		}
		_ = windows.CloseHandle(h)
	}
	if opened == 0 {
		if mem, found := tasklistAgentMemMB(); found {
			return 0, mem, "", true
		}
		return 0, 0, "", false
	}

	memMB = float64(wsBytes) / (1024 * 1024)
	if haveCreate && created.Nanoseconds() > 0 {
		uptime = processStartUptime(time.Unix(0, created.Nanoseconds()))
	}

	cpuMu.Lock()
	defer cpuMu.Unlock()
	now := time.Now()
	if !lastCPUAt.IsZero() && ticks >= lastCPUTicks {
		wall := now.Sub(lastCPUAt).Seconds()
		if wall > 0.05 {
			delta := float64(ticks-lastCPUTicks) / 1e7 // FILETIME 100ns → seconds
			n := float64(windows.GetActiveProcessorCount(0xFFFF))
			if n < 1 {
				n = float64(1)
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
	lastCPUAt = now
	lastCPUTicks = ticks
	return cpu, memMB, uptime, true
}

func edrAgentPIDs() []uint32 {
	seen := map[uint32]struct{}{}
	var out []uint32
	add := func(pid uint32) {
		if pid == 0 {
			return
		}
		if _, ok := seen[pid]; ok {
			return
		}
		seen[pid] = struct{}{}
		out = append(out, pid)
	}
	if pid := hostperm.SensorPID(); pid != 0 {
		add(pid)
	}
	snap, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return out
	}
	defer windows.CloseHandle(snap)
	var pe windows.ProcessEntry32
	pe.Size = uint32(unsafe.Sizeof(pe))
	if err := windows.Process32First(snap, &pe); err != nil {
		return out
	}
	for {
		name := strings.ToLower(windows.UTF16ToString(pe.ExeFile[:]))
		if name == "edr-agent.exe" {
			add(pe.ProcessID)
		}
		if err := windows.Process32Next(snap, &pe); err != nil {
			break
		}
	}
	return out
}

func processWorkingSet(h windows.Handle) (processMemoryCounters, error) {
	var pmc processMemoryCounters
	pmc.CB = uint32(unsafe.Sizeof(pmc))
	r, _, err := procK32GetProcessMemoryInfo.Call(uintptr(h), uintptr(unsafe.Pointer(&pmc)), uintptr(pmc.CB))
	if r == 0 {
		return pmc, err
	}
	return pmc, nil
}

func processCPUTicks(h windows.Handle) uint64 {
	var create, exit, kernel, user windows.Filetime
	if err := windows.GetProcessTimes(h, &create, &exit, &kernel, &user); err != nil {
		return 0
	}
	return filetimeTicks(kernel) + filetimeTicks(user)
}

func filetimeTicks(ft windows.Filetime) uint64 {
	return uint64(ft.HighDateTime)<<32 | uint64(ft.LowDateTime)
}

func tasklistAgentMemMB() (float64, bool) {
	cmd := exec.Command("tasklist", "/FI", "IMAGENAME eq edr-agent.exe", "/FO", "CSV", "/NH")
	hideConsole(cmd)
	out, err := cmd.Output()
	if err != nil {
		return 0, false
	}
	return parseTasklistMemMB(string(out))
}
