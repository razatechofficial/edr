//go:build linux || darwin

package actions

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
)

func verifyPIDExists(pid uint32) bool {
	if pid == 0 {
		return false
	}
	p, err := os.FindProcess(int(pid))
	if err != nil {
		return false
	}
	err = p.Signal(syscall.Signal(0))
	_ = p.Release()
	return err == nil
}

func killOne(pid uint32) error {
	if !verifyPIDExists(pid) {
		return fmt.Errorf("process %d does not exist", pid)
	}
	return syscall.Kill(int(pid), syscall.SIGKILL)
}

func getChildPIDs(ctx context.Context, parent uint32) ([]uint32, error) {
	switch runtime.GOOS {
	case "linux":
		return getChildPIDsLinux(uint32(parent))
	default:
		return getChildPIDsPS(ctx, uint32(parent))
	}
}

func getChildPIDsLinux(parent uint32) ([]uint32, error) {
	ents, err := os.ReadDir("/proc")
	if err != nil {
		return nil, err
	}
	var out []uint32
	for _, e := range ents {
		if !e.IsDir() {
			continue
		}
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		if uint32(pid) == parent {
			continue
		}
		b, err := os.ReadFile(filepath.Join("/proc", e.Name(), "status"))
		if err != nil {
			continue
		}
		for _, line := range strings.Split(string(b), "\n") {
			if strings.HasPrefix(line, "PPid:") {
				parts := strings.Fields(line)
				if len(parts) < 2 {
					break
				}
				pp, err := strconv.Atoi(parts[1])
				if err != nil {
					break
				}
				if uint32(pp) == parent {
					out = append(out, uint32(pid))
				}
				break
			}
		}
	}
	return out, nil
}

func getChildPIDsPS(ctx context.Context, parent uint32) ([]uint32, error) {
	// ps -axo pid=,ppid= (macOS/BSD)
	cmd := exec.CommandContext(ctx, "ps", "-axo", "pid=,ppid=")
	out, err := cmd.Output()
	if err != nil {
		return nil, err
	}
	var children []uint32
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		pid, err1 := strconv.Atoi(fields[0])
		ppid, err2 := strconv.Atoi(fields[1])
		if err1 != nil || err2 != nil {
			continue
		}
		if uint32(ppid) == parent {
			children = append(children, uint32(pid))
		}
	}
	return children, nil
}
