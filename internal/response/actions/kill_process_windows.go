//go:build windows

package actions

import (
	"context"
	"fmt"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

func verifyPIDExists(pid uint32) bool {
	if pid == 0 {
		return false
	}
	const da = syscall.STANDARD_RIGHTS_READ | 0x1000
	h, err := windows.OpenProcess(da, false, uint32(pid))
	if err != nil {
		return false
	}
	_ = windows.CloseHandle(h)
	return true
}

func killOne(pid uint32) error {
	if !verifyPIDExists(pid) {
		return fmt.Errorf("process %d does not exist", pid)
	}
	h, err := windows.OpenProcess(windows.PROCESS_TERMINATE, false, uint32(pid))
	if err != nil {
		return err
	}
	defer windows.CloseHandle(h)
	return windows.TerminateProcess(h, 1)
}

func getChildPIDs(_ context.Context, parent uint32) ([]uint32, error) {
	s, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return nil, err
	}
	defer windows.CloseHandle(s)
	var pe windows.ProcessEntry32
	pe.Size = uint32(unsafe.Sizeof(pe))
	if err := windows.Process32First(s, &pe); err != nil {
		return nil, err
	}
	var out []uint32
	for {
		if pe.ParentProcessID == parent {
			out = append(out, pe.ProcessID)
		}
		if err := windows.Process32Next(s, &pe); err != nil {
			break
		}
	}
	return out, nil
}
