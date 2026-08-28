package main

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"

	"github.com/razatechofficial/edr/internal/platform"
)

type resourceSnapshot struct {
	SysCPU     float64
	SysMemUsed uint64
	SysMemTot  uint64
	AgentCPU   float64
	AgentMemMB float64
	OtherCPU   float64
	OtherMem   uint64
	FreeMem    uint64
}

func sampleResources(st operatorStatus) resourceSnapshot {
	cpu, used, total := sampleSystem()
	agentCPU, agentMem := 0.0, 0.0
	if c, m, _, ok := sampleAgentProcess(); ok {
		agentCPU, agentMem = c, m
	} else {
		agentCPU, agentMem = st.CPUPercent, st.MemoryMB
	}
	if agentCPU < 0 {
		agentCPU = 0
	}
	if agentMem < 0 {
		agentMem = 0
	}
	agentBytes := uint64(agentMem * 1024 * 1024)
	if total > 0 && agentBytes > total {
		agentBytes = total
		agentMem = float64(agentBytes) / (1024 * 1024)
	}
	if used < agentBytes {
		used = agentBytes
	}
	if total > 0 && used > total {
		used = total
	}
	otherMem := used - agentBytes
	free := uint64(0)
	if total > used {
		free = total - used
	}
	if cpu > 100 {
		cpu = 100
	}
	// ps/%cpu is per logical core; SysCPU is whole-machine. Convert before subtracting.
	otherCPU := cpu - agentCPUShare(agentCPU)
	if otherCPU < 0 {
		otherCPU = 0
	}
	return resourceSnapshot{
		SysCPU:     cpu,
		SysMemUsed: used,
		SysMemTot:  total,
		AgentCPU:   agentCPU,
		AgentMemMB: agentMem,
		OtherCPU:   otherCPU,
		OtherMem:   otherMem,
		FreeMem:    free,
	}
}

func agentCPUShare(agentCPU float64) float64 {
	n := float64(runtime.NumCPU())
	if n < 1 {
		n = 1
	}
	share := agentCPU / n
	if share < 0 {
		return 0
	}
	return share
}

func busyCPU(idle0, total0, idle1, total1 uint64) float64 {
	if total1 <= total0 {
		return 0
	}
	dtotal := total1 - total0
	didle := idle1 - idle0
	if didle > dtotal {
		return 0
	}
	pct := (1 - float64(didle)/float64(dtotal)) * 100
	if pct < 0 {
		return 0
	}
	if pct > 100 {
		return 100
	}
	return pct
}

func (s resourceSnapshot) memShares() (edr, other, free float64) {
	tot := float64(s.SysMemTot)
	if tot < 1 {
		return 0, 0, 1
	}
	edr = float64(uint64(s.AgentMemMB*1024*1024)) / tot
	other = float64(s.OtherMem) / tot
	free = float64(s.FreeMem) / tot
	return edr, other, free
}

func (s resourceSnapshot) cpuShares() (edr, other, idle float64) {
	edr = agentCPUShare(s.AgentCPU) / 100
	other = s.OtherCPU / 100
	idle = 1 - edr - other
	if idle < 0 {
		idle = 0
	}
	return edr, other, idle
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
