package kernel

import "sort"

// sortedUint32Percentile returns the nearest-rank p-percentile (p in [0,100]) over a copy of samples.
func sortedUint32Percentile(samples []uint32, p int) int {
	if len(samples) == 0 || p < 0 || p > 100 {
		return 0
	}
	cp := append([]uint32(nil), samples...)
	sort.Slice(cp, func(i, j int) bool { return cp[i] < cp[j] })
	if p == 100 {
		return int(cp[len(cp)-1])
	}
	if p == 0 {
		return int(cp[0])
	}
	// Nearest rank: ceil(p/100 * n)
	k := (len(cp)*p + 99) / 100
	if k < 1 {
		k = 1
	}
	if k > len(cp) {
		k = len(cp)
	}
	return int(cp[k-1])
}
