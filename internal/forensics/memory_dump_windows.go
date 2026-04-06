//go:build windows

package forensics

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	modKernel32        = windows.NewLazyDLL("kernel32.dll")
	procVirtualQueryEx = modKernel32.NewProc("VirtualQueryEx")
	procReadProcMem    = modKernel32.NewProc("ReadProcessMemory")
)

const (
	memCommit        = 0x1000
	pageNoAccess     = 0x01
	pageGuard        = 0x100
	winMaxChunk      = 64 * 1024 * 1024
)

type memoryBasicInfo struct {
	BaseAddress       uintptr
	AllocationBase    uintptr
	AllocationProtect uint32
	pad0              uint32
	RegionSize        uintptr
	State             uint32
	Protect           uint32
	Type              uint32
	pad1              uint32
}

// dumpProcessMemory acquires process memory on Windows using VirtualQueryEx
// and ReadProcessMemory.
func dumpProcessMemory(ctx context.Context, pid int, dumpDir string) ([]MemoryRegion, error) {
	handle, err := windows.OpenProcess(
		windows.PROCESS_VM_READ|windows.PROCESS_QUERY_INFORMATION,
		false, uint32(pid))
	if err != nil {
		return nil, fmt.Errorf("OpenProcess(%d): %w", pid, err)
	}
	defer windows.CloseHandle(handle)

	var regions []MemoryRegion
	var addr uintptr
	infoSize := unsafe.Sizeof(memoryBasicInfo{})

	for {
		select {
		case <-ctx.Done():
			return regions, ctx.Err()
		default:
		}

		var info memoryBasicInfo
		ret, _, _ := procVirtualQueryEx.Call(
			uintptr(handle), addr,
			uintptr(unsafe.Pointer(&info)), infoSize)
		if ret == 0 {
			break
		}

		region := MemoryRegion{
			Start:      uint64(info.BaseAddress),
			End:        uint64(info.BaseAddress) + uint64(info.RegionSize),
			Size:       uint64(info.RegionSize),
			Protection: fmtWinProt(info.Protect),
		}

		if info.State == memCommit && isReadableProt(info.Protect) {
			regionPath := filepath.Join(dumpDir,
				fmt.Sprintf("region_%016x_%016x.bin",
					info.BaseAddress, info.BaseAddress+info.RegionSize))
			if err := readWinRegion(handle, info.BaseAddress, info.RegionSize, regionPath); err == nil {
				region.Dumped = true
			}
		}

		regions = append(regions, region)
		addr = info.BaseAddress + info.RegionSize
	}
	return regions, nil
}

func readWinRegion(handle windows.Handle, addr, size uintptr, dst string) error {
	f, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer f.Close()

	remaining := size
	offset := addr
	for remaining > 0 {
		chunk := remaining
		if chunk > winMaxChunk {
			chunk = winMaxChunk
		}
		buf := make([]byte, chunk)
		var bytesRead uintptr
		ret, _, _ := procReadProcMem.Call(
			uintptr(handle), offset,
			uintptr(unsafe.Pointer(&buf[0])), chunk,
			uintptr(unsafe.Pointer(&bytesRead)))
		if ret == 0 || bytesRead == 0 {
			break
		}
		if _, err := f.Write(buf[:bytesRead]); err != nil {
			return err
		}
		offset += bytesRead
		remaining -= bytesRead
	}
	return nil
}

func isReadableProt(p uint32) bool {
	return p != pageNoAccess && p&pageGuard == 0
}

func fmtWinProt(p uint32) string {
	switch p {
	case 0x02:
		return "r--"
	case 0x04:
		return "rw-"
	case 0x08:
		return "rw-"
	case 0x10:
		return "--x"
	case 0x20:
		return "r-x"
	case 0x40:
		return "rwx"
	default:
		return fmt.Sprintf("%#04x", p)
	}
}
