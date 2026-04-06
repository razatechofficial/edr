//go:build linux

package forensics

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

const maxRegionRead = 64 * 1024 * 1024 // 64 MiB per read chunk

// dumpProcessMemory reads /proc/PID/maps to enumerate regions and
// /proc/PID/mem for the raw content of each readable region.
func dumpProcessMemory(ctx context.Context, pid int, dumpDir string) ([]MemoryRegion, error) {
	mapsPath := fmt.Sprintf("/proc/%d/maps", pid)
	regions, err := parseProcMaps(mapsPath)
	if err != nil {
		return nil, fmt.Errorf("parse maps: %w", err)
	}

	memPath := fmt.Sprintf("/proc/%d/mem", pid)
	memFile, err := os.Open(memPath)
	if err != nil {
		return regions, fmt.Errorf("open mem: %w", err)
	}
	defer memFile.Close()

	for i := range regions {
		select {
		case <-ctx.Done():
			return regions, ctx.Err()
		default:
		}

		r := &regions[i]
		if !strings.Contains(r.Protection, "r") || r.Size == 0 {
			continue
		}

		regionFile := filepath.Join(dumpDir,
			fmt.Sprintf("region_%016x_%016x.bin", r.Start, r.End))
		if err := readRegionToFile(memFile, int64(r.Start), int64(r.Size), regionFile); err == nil {
			r.Dumped = true
		}
	}
	return regions, nil
}

func parseProcMaps(path string) ([]MemoryRegion, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var regions []MemoryRegion
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		parts := strings.Fields(line)
		if len(parts) < 2 {
			continue
		}
		addrRange := strings.SplitN(parts[0], "-", 2)
		if len(addrRange) != 2 {
			continue
		}
		start, err := strconv.ParseUint(addrRange[0], 16, 64)
		if err != nil {
			continue
		}
		end, err := strconv.ParseUint(addrRange[1], 16, 64)
		if err != nil {
			continue
		}

		var pathname string
		if len(parts) >= 6 {
			pathname = parts[5]
		}

		regions = append(regions, MemoryRegion{
			Start:      start,
			End:        end,
			Size:       end - start,
			Protection: parts[1],
			Pathname:   pathname,
		})
	}
	return regions, scanner.Err()
}

func readRegionToFile(mem *os.File, offset, size int64, dst string) error {
	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer out.Close()

	remaining := size
	pos := offset
	buf := make([]byte, maxRegionRead)
	for remaining > 0 {
		n := int64(len(buf))
		if n > remaining {
			n = remaining
		}
		nr, err := mem.ReadAt(buf[:n], pos)
		if nr > 0 {
			if _, werr := out.Write(buf[:nr]); werr != nil {
				return werr
			}
		}
		if err != nil && err != io.EOF {
			return err
		}
		pos += int64(nr)
		remaining -= int64(nr)
		if nr == 0 {
			break
		}
	}
	return nil
}
