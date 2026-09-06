//go:build !windows

package agent

import "runtime"

func sampleSelfResources() (cpu, memMB float64) {
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	return 0, float64(ms.Sys) / (1024 * 1024)
}
