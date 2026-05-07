package actions

import (
	"archive/tar"
	"bufio"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/razatechofficial/edr/internal/forensics"
)

// ForensicCollector writes diagnostic bundles under ForensicsDir.
type ForensicCollector struct {
	ForensicsDir string
	DetectionID  string
	Deep         forensics.ForensicsDeepConfig
}

// ForensicBundle is a JSON-serialized snapshot of host state.
type ForensicBundle struct {
	ProcessTree     []ProcessInfo       `json:"process_tree,omitempty"`
	NetworkState    []NetworkConnection `json:"network_state,omitempty"`
	OpenFiles       []OpenFileInfo      `json:"open_files,omitempty"`
	RecentFiles     []RecentFileInfo    `json:"recent_files,omitempty"`
	EnvironmentVars map[string]string   `json:"environment_vars,omitempty"`
	LoadedModules   []ModuleInfo        `json:"loaded_modules,omitempty"`
	DNSCache        []DNSCacheEntry     `json:"dns_cache,omitempty"`
	ARPTable        []ARPEntry          `json:"arp_table,omitempty"`
	CollectedAt     time.Time           `json:"collected_at"`
	DetectionID     string              `json:"detection_id"`
}

type ProcessInfo struct {
	PID  int    `json:"pid"`
	PPID int    `json:"ppid"`
	Name string `json:"name"`
}

type NetworkConnection struct {
	Proto  string `json:"proto"`
	Local  string `json:"local"`
	Remote string `json:"remote"`
	State  string `json:"state"`
}

type OpenFileInfo struct {
	PID  int    `json:"pid"`
	Path string `json:"path"`
}

type RecentFileInfo struct {
	Path string    `json:"path"`
	Mod  time.Time `json:"mod"`
}

type ModuleInfo struct {
	PID  int    `json:"pid"`
	Name string `json:"name"`
	Path string `json:"path"`
}

type DNSCacheEntry struct {
	Name string `json:"name"`
}

type ARPEntry struct {
	IP  string `json:"ip"`
	MAC string `json:"mac"`
}

// Collect runs collectors for each item name; writes under absolute ForensicsDir only.
func (c *ForensicCollector) Collect(ctx context.Context, items []string) (bundle *ForensicBundle, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("collect_forensics panic: %v", r)
		}
	}()
	if c.ForensicsDir == "" {
		return nil, fmt.Errorf("forensics_dir required")
	}
	abs, err := filepath.Abs(c.ForensicsDir)
	if err != nil {
		return nil, err
	}
	if !filepath.IsAbs(abs) {
		return nil, fmt.Errorf("forensics dir must be absolute")
	}
	bundle = &ForensicBundle{
		CollectedAt: time.Now().UTC(),
		DetectionID: c.DetectionID,
	}
	for _, item := range items {
		switch item {
		case "process_tree":
			bundle.ProcessTree = c.collectProcessTree(ctx)
		case "network_state", "network_connections":
			bundle.NetworkState = c.collectNetworkState()
		case "open_files":
			bundle.OpenFiles = c.collectOpenFiles(ctx)
		case "memory_dump":
			_ = c.runMemoryDumpPlaceholder()
		}
	}
	outDir := filepath.Join(abs, c.DetectionID)
	if err := os.MkdirAll(outDir, 0o700); err != nil {
		return nil, err
	}
	if c.Deep.AnyEnabled() {
		files := forensics.CollectDeepToWorkdir(outDir, c.Deep)
		raw, _ := json.MarshalIndent(files, "", "  ")
		_ = os.WriteFile(filepath.Join(outDir, "deep_collected.json"), raw, 0o600)
	}
	data, _ := json.MarshalIndent(bundle, "", "  ")
	jpath := filepath.Join(outDir, "bundle.json")
	if err := writeFileExclusive(jpath, data, 0o600); err != nil {
		return nil, err
	}
	_ = c.compressDir(outDir)
	return bundle, nil
}

func writeFileExclusive(path string, data []byte, mode os.FileMode) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, mode)
	if err != nil {
		return err
	}
	_, werr := f.Write(data)
	cerr := f.Close()
	if werr != nil {
		return werr
	}
	return cerr
}

func (c *ForensicCollector) runMemoryDumpPlaceholder() error { return nil }

func (c *ForensicCollector) collectProcessTree(ctx context.Context) []ProcessInfo {
	switch runtime.GOOS {
	case "linux":
		return collectProcTreeLinux()
	case "windows":
		out, err := exec.CommandContext(ctx, "tasklist", "/fo", "csv", "/nh").Output()
		if err != nil {
			return nil
		}
		// keep minimal
		_ = out
		return nil
	case "darwin":
		out, err := exec.CommandContext(ctx, "ps", "-axo", "pid,ppid,comm").Output()
		if err != nil {
			return nil
		}
		var res []ProcessInfo
		scan := bufio.NewScanner(strings.NewReader(string(out)))
		for scan.Scan() {
			var pid, ppid int
			var comm string
			_, e := fmt.Sscan(scan.Text(), &pid, &ppid, &comm)
			if e != nil {
				continue
			}
			res = append(res, ProcessInfo{PID: pid, PPID: ppid, Name: comm})
		}
		return res
	}
	return nil
}

func collectProcTreeLinux() []ProcessInfo {
	ents, err := os.ReadDir("/proc")
	if err != nil {
		return nil
	}
	var out []ProcessInfo
	for _, e := range ents {
		if !e.IsDir() {
			continue
		}
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		b, _ := os.ReadFile(filepath.Join("/proc", e.Name(), "status"))
		pi := ProcessInfo{PID: pid}
		for _, line := range strings.Split(string(b), "\n") {
			if strings.HasPrefix(line, "Name:") {
				pi.Name = strings.TrimSpace(strings.TrimPrefix(line, "Name:"))
			}
			if strings.HasPrefix(line, "PPid:") {
				_, _ = fmt.Sscan(strings.TrimPrefix(line, "PPid:"), &pi.PPID)
			}
		}
		out = append(out, pi)
	}
	return out
}

func (c *ForensicCollector) collectNetworkState() []NetworkConnection {
	if runtime.GOOS == "linux" {
		return parseProcNet("tcp", "/proc/net/tcp")
	}
	// non-Linux: /proc is unavailable; extend with eBPF, iproute, or per-OS net libraries if required.
	return nil
}

func parseProcNet(proto, path string) []NetworkConnection {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var out []NetworkConnection
	lines := strings.Split(string(b), "\n")
	for i, line := range lines {
		if i == 0 {
			continue
		}
		if strings.TrimSpace(line) == "" {
			continue
		}
		out = append(out, NetworkConnection{Proto: proto, Local: line, Remote: line})
	}
	return out
}

func (c *ForensicCollector) collectOpenFiles(ctx context.Context) []OpenFileInfo {
	_ = ctx
	return nil
}

func (c *ForensicCollector) compressDir(dir string) error {
	if dir == "" {
		return nil
	}
	dir, err := filepath.Abs(dir)
	if err != nil {
		return err
	}
	if _, err := os.Stat(dir); err != nil {
		return err
	}
	tgz := dir + ".tar.gz"
	f, err := os.Create(tgz)
	if err != nil {
		return err
	}
	defer f.Close()
	gw := gzip.NewWriter(f)
	defer gw.Close()
	tw := tar.NewWriter(gw)
	defer tw.Close()
	return filepath.WalkDir(dir, func(path string, d os.DirEntry, werr error) error {
		if werr != nil {
			return werr
		}
		rel, err := filepath.Rel(dir, path)
		if err != nil {
			return err
		}
		if rel == "." {
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		if info.IsDir() {
			hdr, err := tar.FileInfoHeader(info, "")
			if err != nil {
				return err
			}
			hdr.Name = rel + string(filepath.Separator)
			if err := tw.WriteHeader(hdr); err != nil {
				return err
			}
			return nil
		}
		hdr, err := tar.FileInfoHeader(info, "")
		if err != nil {
			return err
		}
		hdr.Name = rel
		if err := tw.WriteHeader(hdr); err != nil {
			return err
		}
		if !info.Mode().IsRegular() {
			return nil
		}
		sf, err := os.Open(path)
		if err != nil {
			return err
		}
		_, cpyErr := io.Copy(tw, sf)
		_ = sf.Close()
		return cpyErr
	})
}
