//go:build linux

package collector

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

func (p *PostureCollector) runOptionalPostureProbes(ctx context.Context) {
	if p == nil || len(p.cfg.Monitoring.PostureProbes) == 0 {
		return
	}
	out := map[string]any{}
	for _, raw := range p.cfg.Monitoring.PostureProbes {
		name := strings.ToLower(strings.TrimSpace(raw))
		if ctx.Err() != nil {
			break
		}
		switch name {
		case "posture_suid_sweep":
			out[name] = postureSuidSweepLinux(ctx)
		case "posture_hidden_pid":
			out[name] = postureHiddenPIDLinux(ctx)
		case "posture_hidden_port":
			out[name] = map[string]any{"status": "skipped", "reason": "bind_crosscheck_not_implemented"}
		case "posture_dev_walker":
			out[name] = postureDevWalkerLinux(ctx)
		default:
			out[name] = map[string]any{"status": "unknown_probe"}
		}
	}
	p.mu.Lock()
	p.probeOut = out
	p.mu.Unlock()
}


func postureSuidSweepLinux(ctx context.Context) map[string]any {
	const maxWalk = 8000
	var suid int
	var sample []string
	dirs := []string{"/usr/bin", "/usr/sbin", "/bin", "/sbin"}
	for _, root := range dirs {
		_ = filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
			if err != nil || ctx.Err() != nil {
				return nil
			}
			if d.IsDir() {
				return nil
			}
			info, err := d.Info()
			if err != nil {
				return nil
			}
			if info.Mode()&os.ModeSetuid != 0 {
				suid++
				if len(sample) < 12 {
					sample = append(sample, path)
				}
			}
			if suid+len(sample) > maxWalk {
				return filepath.SkipAll
			}
			return nil
		})
	}
	h := sha256.Sum256([]byte(strings.Join(sample, "\n")))
	return map[string]any{
		"suid_count":     suid,
		"sample_sha256":  hex.EncodeToString(h[:]),
		"sample_paths_n": len(sample),
	}
}

func postureHiddenPIDLinux(ctx context.Context) map[string]any {
	ents, err := os.ReadDir("/proc")
	if err != nil {
		return map[string]any{"error": err.Error()}
	}
	var suspicious int
	var checked int
	for _, e := range ents {
		if ctx.Err() != nil {
			break
		}
		if !e.IsDir() {
			continue
		}
		var pid int
		if _, err := fmt.Sscanf(e.Name(), "%d", &pid); err != nil || pid <= 0 {
			continue
		}
		checked++
		if err := syscall.Kill(pid, 0); err != nil {
			suspicious++
		}
		if checked > 4000 {
			break
		}
	}
	return map[string]any{"proc_entries_checked": checked, "kill_zero_failures": suspicious}
}

func postureDevWalkerLinux(ctx context.Context) map[string]any {
	var regFiles int
	var sample []string
	_ = filepath.WalkDir("/dev", func(path string, d os.DirEntry, err error) error {
		if err != nil || ctx.Err() != nil {
			return nil
		}
		if d.IsDir() {
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return nil
		}
		if info.Mode().IsRegular() {
			regFiles++
			if len(sample) < 8 {
				sample = append(sample, path)
			}
		}
		if regFiles > 200 {
			return filepath.SkipAll
		}
		return nil
	})
	return map[string]any{"unexpected_regular_files": regFiles, "sample": sample}
}
