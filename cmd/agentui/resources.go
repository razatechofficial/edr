package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/razatechofficial/edr/internal/platform"
)

const requiredStorageBytes = 2 * 1024 * 1024 * 1024

type resourceSnapshot struct {
	SysCPU     float64
	SysMemUsed uint64
	SysMemTot  uint64
	AgentCPU   float64
	AgentMemMB float64
}

func sampleResources(st operatorStatus) resourceSnapshot {
	cpu, used, total := sampleSystem()
	return resourceSnapshot{
		SysCPU:     cpu,
		SysMemUsed: used,
		SysMemTot:  total,
		AgentCPU:   st.CPUPercent,
		AgentMemMB: st.MemoryMB,
	}
}

func diskFreeBytes(path string) (uint64, error) {
	p := path
	var last error
	for i := 0; i < 8; i++ {
		n, err := diskFree(p)
		if err == nil {
			return n, nil
		}
		last = err
		parent := filepath.Dir(p)
		if parent == p {
			break
		}
		p = parent
	}
	if last == nil {
		last = os.ErrNotExist
	}
	return 0, last
}

func storageCheck() (ok bool, detail string) {
	path := platform.DataDir()
	free, err := diskFreeBytes(path)
	if err != nil {
		return false, "Could not measure free space on the data volume"
	}
	gb := float64(free) / float64(1<<30)
	if free < requiredStorageBytes {
		return false, fmt.Sprintf("%.1f GB free, 2.0 GB required", gb)
	}
	return true, fmt.Sprintf("%.1f GB available", gb)
}

func formatBytesGB(n uint64) string {
	return fmt.Sprintf("%.1f GB", float64(n)/float64(1<<30))
}
