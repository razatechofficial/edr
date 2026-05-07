//go:build windows

package forensics

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

const pageSample = 4096

func collectSelectedPageMemoryWindows(cfg *ForensicsDeepConfig, bundle *DeepArtifactsBundle) {
	budget := cfg.SelectedPageMemoryMaxBytes
	if budget <= 0 {
		budget = defaultSelectedPageMemBytes
	}

	snap, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		bundle.PageMemoryError = err.Error()
		return
	}
	defer windows.CloseHandle(snap)

	var pe windows.ProcessEntry32
	pe.Size = uint32(unsafe.Sizeof(pe))
	if err := windows.Process32First(snap, &pe); err != nil {
		bundle.PageMemoryError = err.Error()
		return
	}

	infoSize := unsafe.Sizeof(memoryBasicInfo{})
	for {
		if budget < pageSample {
			break
		}
		pid := pe.ProcessID
		name := windows.UTF16ToString(pe.ExeFile[:])
		if pid != 0 && pid != 4 {
			if h, err := windows.OpenProcess(
				windows.PROCESS_VM_READ|windows.PROCESS_QUERY_INFORMATION,
				false, pid); err == nil {
				func() {
					defer windows.CloseHandle(h)
					var addr uintptr
					for budget >= pageSample {
						var info memoryBasicInfo
						ret, _, _ := procVirtualQueryEx.Call(
							uintptr(h), addr,
							uintptr(unsafe.Pointer(&info)), infoSize)
						if ret == 0 {
							break
						}
						next := info.BaseAddress + info.RegionSize
						if info.State == memCommit && isReadableProt(info.Protect) {
							toRead := pageSample
							if uintptr(toRead) > info.RegionSize {
								toRead = int(info.RegionSize)
							}
							if toRead <= 0 {
								addr = next
								continue
							}
							buf := make([]byte, toRead)
							var br uintptr
							ok, _, _ := procReadProcMem.Call(
								uintptr(h), info.BaseAddress,
								uintptr(unsafe.Pointer(&buf[0])), uintptr(toRead),
								uintptr(unsafe.Pointer(&br)))
							if ok != 0 && br > 0 {
								sum := sha256.Sum256(buf[:br])
								bundle.SelectedPageMemory = append(bundle.SelectedPageMemory, PageMemoryChunk{
									PID:       int(pid),
									Name:      name,
									BaseHex:   fmt.Sprintf("%x", info.BaseAddress),
									BytesRead: int(br),
									SHA256:    hex.EncodeToString(sum[:]),
								})
								budget -= int(br)
							}
							break
						}
						addr = next
					}
				}()
			}
		}
		if err := windows.Process32Next(snap, &pe); err != nil {
			break
		}
	}
}
