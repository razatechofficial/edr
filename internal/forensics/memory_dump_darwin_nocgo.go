//go:build darwin && !cgo

package forensics

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
)

// dumpProcessMemory acquires process memory on macOS without cgo by shelling
// out to lldb or vmmap. This is the fallback when cgo is disabled.
func dumpProcessMemory(ctx context.Context, pid int, dumpDir string) ([]MemoryRegion, error) {
	regions, err := vmmapRegions(pid)
	if err != nil {
		return nil, fmt.Errorf("vmmap: %w", err)
	}

	cmd := exec.CommandContext(ctx, "lldb",
		"-p", strconv.Itoa(pid),
		"-o", fmt.Sprintf("process save-core %s", filepath.Join(dumpDir, "core")),
		"-o", "quit",
	)
	if out, err := cmd.CombinedOutput(); err != nil {
		return regions, fmt.Errorf("lldb core dump failed (output: %s): %w",
			strings.TrimSpace(string(out)), err)
	}

	for i := range regions {
		regions[i].Dumped = true
	}
	return regions, nil
}

func vmmapRegions(pid int) ([]MemoryRegion, error) {
	out, err := exec.Command("vmmap", "-wide", strconv.Itoa(pid)).Output()
	if err != nil {
		return nil, err
	}

	var regions []MemoryRegion
	scanner := bufio.NewScanner(strings.NewReader(string(out)))
	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.Fields(line)
		if len(fields) < 3 || !strings.Contains(fields[1], "-") {
			continue
		}
		parts := strings.SplitN(fields[1], "-", 2)
		if len(parts) != 2 {
			continue
		}
		start, err1 := strconv.ParseUint(parts[0], 16, 64)
		end, err2 := strconv.ParseUint(parts[1], 16, 64)
		if err1 != nil || err2 != nil {
			continue
		}
		prot := "---"
		if len(fields) > 3 {
			prot = fields[3]
		}
		regions = append(regions, MemoryRegion{
			Start:      start,
			End:        end,
			Size:       end - start,
			Protection: prot,
			Pathname:   fields[0],
		})
	}
	return regions, nil
}

func init() {
	_ = os.MkdirAll("/tmp", 0755)
}
