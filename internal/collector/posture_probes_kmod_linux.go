//go:build linux

package collector

import (
	"bufio"
	"os"
	"strings"
)

func postureKmodSummaryLinux() map[string]any {
	f, err := os.Open("/proc/modules")
	if err != nil {
		return map[string]any{"error": err.Error()}
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	n := 0
	var sample []string
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		n++
		fields := strings.Fields(line)
		if len(fields) > 0 && len(sample) < 12 {
			sample = append(sample, fields[0])
		}
	}
	if err := sc.Err(); err != nil {
		return map[string]any{"error": err.Error()}
	}
	return map[string]any{"loaded_modules": n, "sample": sample}
}
