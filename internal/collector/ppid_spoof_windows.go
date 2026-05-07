//go:build windows

package collector

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

const processInfoClassBasic = 0

type processBasicInformation struct {
	Reserved1                    uintptr
	PebBaseAddress               uintptr
	Reserved2                    uintptr
	Reserved3                    uintptr
	UniqueProcessId              uintptr
	InheritedFromUniqueProcessID uintptr
}

var (
	modNT     = windows.NewLazySystemDLL("ntdll.dll")
	procNtQIP = modNT.NewProc("NtQueryInformationProcess")
)

func ntInheritedFromPID(pid uint32) (uint32, error) {
	modNT.Load()
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return 0, err
	}
	defer windows.CloseHandle(h)
	var pbi processBasicInformation
	var retLen uint32
	r, _, _ := procNtQIP.Call(
		uintptr(h),
		uintptr(processInfoClassBasic),
		uintptr(unsafe.Pointer(&pbi)),
		uintptr(unsafe.Sizeof(pbi)),
		uintptr(unsafe.Pointer(&retLen)),
	)
	if r != 0 {
		return 0, fmt.Errorf("NtQueryInformationProcess status=0x%x", r)
	}
	return uint32(pbi.InheritedFromUniqueProcessID), nil
}

func (kc *KernelCollector) maybeDetectPPIDSpoof(tel *Telemetry) {
	if kc == nil || !kc.cfg.Monitoring.WindowsPPIDSpoofDetector || tel == nil || tel.Process == nil {
		return
	}
	pe := tel.Process
	if pe.ChildPID == 0 {
		return
	}
	if pe.PID != pe.ChildPID {
		return
	}
	inh, err := ntInheritedFromPID(uint32(pe.PID))
	if err != nil || inh == 0 || pe.PPID <= 0 {
		return
	}
	kc.ppidChecks.Add(1)
	if inh != uint32(pe.PPID) {
		kc.ppidMismatch.Add(1)
		pe.Tags = append(pe.Tags, "detection", "ppid_spoof")
		pe.Severity = "high"
		if pe.CommandLine != "" {
			pe.CommandLine += " "
		}
		pe.CommandLine += fmt.Sprintf("|edr_inherited_ppid=%d etw_ppid=%d", inh, pe.PPID)
	}
}
