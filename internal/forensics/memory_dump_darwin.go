//go:build darwin

package forensics

/*
#include <mach/mach.h>
#include <mach/mach_vm.h>

// mach_task_self() and current_task() are macros; wrap for cgo.
static mach_port_t edr_self_task(void) { return mach_task_self(); }

// vm_offset_t is an integer holding a pointer value; cast in C so Go's
// unsafe.Pointer rules are not violated.
static void* offset_ptr(vm_offset_t v) { return (void*)v; }
*/
import "C"

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"unsafe"
)

const machMaxChunk = 64 * 1024 * 1024 // 64 MiB

// dumpProcessMemory acquires process memory on macOS using task_for_pid and
// mach_vm_read. Requires root or the com.apple.security.cs.debugger
// entitlement.
func dumpProcessMemory(ctx context.Context, pid int, dumpDir string) ([]MemoryRegion, error) {
	var task C.mach_port_t
	kr := C.task_for_pid(C.edr_self_task(), C.int(pid), &task)
	if kr != C.KERN_SUCCESS {
		return nil, fmt.Errorf("task_for_pid(%d): kern_return=%d "+
			"(requires root or com.apple.security.cs.debugger)", pid, int(kr))
	}
	defer C.mach_port_deallocate(C.edr_self_task(), task)

	var regions []MemoryRegion
	var address C.mach_vm_address_t

	for {
		select {
		case <-ctx.Done():
			return regions, ctx.Err()
		default:
		}

		var size C.mach_vm_size_t
		var info C.vm_region_basic_info_data_64_t
		var count C.mach_msg_type_number_t = C.VM_REGION_BASIC_INFO_COUNT_64
		var objectName C.mach_port_t

		kr = C.mach_vm_region(task, &address, &size,
			C.VM_REGION_BASIC_INFO_64,
			C.vm_region_info_t(unsafe.Pointer(&info)), &count, &objectName)
		if kr != C.KERN_SUCCESS {
			break
		}

		region := MemoryRegion{
			Start:      uint64(address),
			End:        uint64(address) + uint64(size),
			Size:       uint64(size),
			Protection: formatMachProt(uint32(info.protection)),
		}

		if info.protection&C.VM_PROT_READ != 0 && size > 0 {
			regionPath := filepath.Join(dumpDir,
				fmt.Sprintf("region_%016x_%016x.bin", uint64(address), uint64(address)+uint64(size)))
			if err := readMachRegion(task, address, size, regionPath); err == nil {
				region.Dumped = true
			}
		}

		regions = append(regions, region)
		address += C.mach_vm_address_t(size)
	}
	return regions, nil
}

func readMachRegion(task C.mach_port_t, addr C.mach_vm_address_t, size C.mach_vm_size_t, dst string) error {
	f, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer f.Close()

	remaining := size
	offset := addr
	for remaining > 0 {
		chunk := remaining
		if chunk > machMaxChunk {
			chunk = machMaxChunk
		}

		var data C.vm_offset_t
		var dataCnt C.mach_msg_type_number_t
		kr := C.mach_vm_read(task, offset, chunk, &data, &dataCnt)
		if kr != C.KERN_SUCCESS || dataCnt == 0 {
			break
		}

		goData := C.GoBytes(C.offset_ptr(data), C.int(dataCnt))
		C.vm_deallocate(C.edr_self_task(), data, C.vm_size_t(dataCnt))

		if _, err := f.Write(goData); err != nil {
			return err
		}
		offset += C.mach_vm_address_t(dataCnt)
		remaining -= C.mach_vm_size_t(dataCnt)
	}
	return nil
}

func formatMachProt(p uint32) string {
	var s [3]byte
	s[0], s[1], s[2] = '-', '-', '-'
	if p&1 != 0 {
		s[0] = 'r'
	}
	if p&2 != 0 {
		s[1] = 'w'
	}
	if p&4 != 0 {
		s[2] = 'x'
	}
	return string(s[:])
}
