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
	dir := filepath.Join(platform.DataDir(), "telemetry-queue")
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return false, "Cannot create the offline event spool directory."
	}
	probe := filepath.Join(dir, ".write-test")
	if err := os.WriteFile(probe, []byte("ok"), 0o600); err != nil {
		return false, "Offline event spool is not writable."
	}
	_ = os.Remove(probe)
	free, err := diskFreeBytes(dir)
	if err == nil && free < 64*1024*1024 {
		return false, fmt.Sprintf("Only %.0f MB free; spool needs room for offline events.", float64(free)/(1<<20))
	}
	if err == nil {
		return true, fmt.Sprintf("Writable · %.1f GB free", float64(free)/float64(1<<30))
	}
	return true, "Spool directory is writable"
}

func formatBytesGB(n uint64) string {
	return fmt.Sprintf("%.1f GB", float64(n)/float64(1<<30))
}
