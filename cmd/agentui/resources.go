package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/razatechofficial/edr/internal/platform"
)

type resourceSnapshot struct {
	SysCPU     float64
	SysMemUsed uint64
	SysMemTot  uint64
	AgentCPU   float64
	AgentMemMB float64
}

func sampleResources(st operatorStatus) resourceSnapshot {
	cpu, used, total := sampleSystem()
	agentCPU, agentMem := st.CPUPercent, st.MemoryMB
	if c, m, _, ok := sampleAgentProcess(); ok {
		if agentCPU == 0 {
			agentCPU = c
		}
		if agentMem == 0 {
			agentMem = m
		}
	}
	return resourceSnapshot{
		SysCPU:     cpu,
		SysMemUsed: used,
		SysMemTot:  total,
		AgentCPU:   agentCPU,
		AgentMemMB: agentMem,
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
	data := platform.DataDir()
	dir := filepath.Join(data, "telemetry-queue")
	info, err := os.Stat(dir)
	if err != nil || !info.IsDir() {
		if _, perr := os.Stat(data); perr != nil {
			return false, "Agent data directory is missing. Reinstall as administrator."
		}
		free, ferr := diskFreeBytes(data)
		if ferr == nil && free < 64*1024*1024 {
			return false, fmt.Sprintf("Only %.0f MB free on the data volume.", float64(free)/(1<<20))
		}
		return true, "Data directory is present. The sensor creates the offline queue on start."
	}
	free, ferr := diskFreeBytes(dir)
	if ferr == nil && free < 64*1024*1024 {
		return false, fmt.Sprintf("Only %.0f MB free; spool needs room for offline events.", float64(free)/(1<<20))
	}
	if ferr == nil {
		return true, fmt.Sprintf("Present · %.1f GB free", float64(free)/float64(1<<30))
	}
	return true, "Offline event spool path is present"
}

func formatBytesGB(n uint64) string {
	return fmt.Sprintf("%.1f GB", float64(n)/float64(1<<30))
}
