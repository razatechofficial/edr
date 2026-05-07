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
			out[name] = postureHiddenPortLinux(ctx)
		case "posture_promisc_if":
			out[name] = posturePromiscInterfacesLinux(ctx)
		case "posture_pkg_integrity":
			out[name] = posturePkgIntegrityLinux(ctx)
		case "posture_kmod_summary":
			out[name] = postureKmodSummaryLinux()
		case "posture_dev_walker":
			out[name] = postureDevWalkerLinux(ctx)
		case "ld_so_preload_hash":
			out[name] = p.probeLdSoPreloadHash()
		case "dev_anomaly":
			out[name] = postureDevAnomalyNonRecursive()
		case "rootkit_iocs":
			out[name] = postureRootkitIOCPaths()
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

// Canonical rootkit-related paths often referenced in public writeups; matches
// are only counted when the path exists as a regular file (not a symlink).
var rootkitIOCPathList = []string{
	"/dev/.udev",
	"/usr/bin/.sshd",
	"/sbin/.mgik",
	"/tmp/.ICE-unix",
	"/lib/libkeyutils.so.1.5",
	"/etc/hosts.deny.bak",
	"/usr/sbin/udhcpc",
	"/bin/.login",
}

func (p *PostureCollector) probeLdSoPreloadHash() map[string]any {
	const path = "/etc/ld.so.preload"
	b, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return map[string]any{"path": path, "exists": false, "sha256": "", "changed": false}
		}
		return map[string]any{"path": path, "error": err.Error()}
	}
	sum := sha256.Sum256(b)
	h := hex.EncodeToString(sum[:])
	var prev string
	var changed bool
	if p != nil {
		p.mu.Lock()
		prev = p.ldPreloadHash
		changed = prev != "" && prev != h
		p.ldPreloadHash = h
		p.mu.Unlock()
	}
	return map[string]any{
		"path":    path,
		"exists":  true,
		"size":    len(b),
		"sha256":  h,
		"changed": changed,
	}
}

// postureDevAnomalyNonRecursive lists unexpected non-device nodes in /dev (non-recursive).
func postureDevAnomalyNonRecursive() map[string]any {
	ents, err := os.ReadDir("/dev")
	if err != nil {
		return map[string]any{"error": err.Error()}
	}
	var anom []string
	for _, e := range ents {
		if e.IsDir() {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		mode := info.Mode()
		if mode&os.ModeSymlink != 0 {
			continue
		}
		isChar := mode&os.ModeCharDevice != 0
		isBlock := mode&os.ModeDevice != 0 && mode&os.ModeCharDevice == 0
		if isChar || isBlock {
			continue
		}
		name := e.Name()
		if name == "core" || name == "stdout" || name == "stderr" {
			continue
		}
		anom = append(anom, filepath.Join("/dev", name))
		if len(anom) > 32 {
			break
		}
	}
	return map[string]any{"anomaly_count": len(anom), "sample": anom}
}

func postureRootkitIOCPaths() map[string]any {
	var hits []string
	for _, pth := range rootkitIOCPathList {
		st, err := os.Lstat(pth)
		if err != nil {
			continue
		}
		if st.Mode().IsRegular() {
			hits = append(hits, pth)
		}
	}
	return map[string]any{"ioc_hits": len(hits), "paths": hits}
}
