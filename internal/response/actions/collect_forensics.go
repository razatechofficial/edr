package actions

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"
)

// ForensicCollector writes diagnostic bundles under ForensicsDir.
type ForensicCollector struct {
	ForensicsDir string
	DetectionID  string
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
	// other OS: return empty
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
	_ = dir
	return nil
}
