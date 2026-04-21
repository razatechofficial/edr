package monitoringdoctor

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/razatechofficial/edr/internal/config"
)

const linuxBPFObject = "/var/lib/edr/bpf/edr.bpf.o"

// Print writes a host monitoring capability report to w.
func Print(w io.Writer, configPath string) error {
	cfg, err := config.Load(configPath)
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}

	fmt.Fprintf(w, "=== EDR monitoring doctor ===\n")
	fmt.Fprintf(w, "config:      %s\n", configPath)
	fmt.Fprintf(w, "os/arch:     %s/%s\n", runtime.GOOS, runtime.GOARCH)
	fmt.Fprintf(w, "monitoring.mode:           %s\n", effectiveMode(cfg))
	fmt.Fprintf(w, "monitoring.kernel_enabled: %v\n", cfg.Monitoring.KernelEnabled)
	fmt.Fprintf(w, "checklist_tier (config):   %q\n", cfg.Monitoring.ChecklistTier)
	fmt.Fprintf(w, "derived_tier:              %s\n", deriveTier(cfg))
	fmt.Fprintf(w, "health_snapshot_sec:       %d\n", cfg.Monitoring.HealthSnapshotSec)
	printMonitoringHealthFile(w, cfg)
	fmt.Fprintln(w)

	switch runtime.GOOS {
	case "linux":
		printLinux(w, cfg)
	case "darwin":
		printDarwin(w, cfg)
	case "windows":
		printWindows(w, cfg)
	default:
		fmt.Fprintf(w, "No OS-specific checks for %s.\n", runtime.GOOS)
	}
	return nil
}

func effectiveMode(cfg config.Config) string {
	if cfg.Monitoring.Mode == "" {
		return "auto"
	}
	return cfg.Monitoring.Mode
}

func deriveTier(cfg config.Config) string {
	if cfg.Monitoring.ChecklistTier != "" {
		return cfg.Monitoring.ChecklistTier
	}
	if cfg.Monitoring.Mode == "userland" || !cfg.Monitoring.KernelEnabled {
		return "userland"
	}
	switch runtime.GOOS {
	case "linux":
		if os.Getuid() == 0 {
			return "kernel_hooks"
		}
	case "darwin":
		if os.Getuid() == 0 {
			return "kernel_hooks"
		}
	case "windows":
		return "kernel_hooks"
	}
	return "userland"
}

func printLinux(w io.Writer, cfg config.Config) {
	fmt.Fprintf(w, "uid: %d euid: %d\n", os.Getuid(), os.Geteuid())
	if os.Getuid() != 0 {
		fmt.Fprintln(w, "PROCESS/FILE/NET kernel: degraded (eBPF needs root)")
	} else {
		fmt.Fprintln(w, "PROCESS/FILE/NET kernel: eligible (root)")
	}
	fmt.Fprintln(w, "eBPF extras: sys_enter_unshare, sys_enter_madvise (rebuild bpf object after pull)")
	fi, err := os.Stat(linuxBPFObject)
	if err != nil {
		fmt.Fprintf(w, "eBPF object %s: missing (%v)\n", linuxBPFObject, err)
	} else if fi.IsDir() {
		fmt.Fprintf(w, "eBPF object %s: unexpected directory\n", linuxBPFObject)
	} else {
		fmt.Fprintf(w, "eBPF object %s: ok (%d bytes)\n", linuxBPFObject, fi.Size())
	}
	if data, err := os.ReadFile("/proc/sys/kernel/unprivileged_bpf_disabled"); err == nil {
		fmt.Fprintf(w, "kernel.unprivileged_bpf_disabled: %s", strings.TrimSpace(string(data)))
		if !strings.HasSuffix(string(data), "\n") {
			fmt.Fprintln(w)
		}
	}
}

func printDarwin(w io.Writer, cfg config.Config) {
	fmt.Fprintf(w, "uid: %d\n", os.Getuid())
	if os.Getuid() != 0 {
		fmt.Fprintln(w, "ESF: degraded (LaunchDaemon root recommended)")
	} else {
		fmt.Fprintln(w, "ESF: root ok (still needs codesign + endpoint-security entitlement)")
	}
	exe, err := os.Executable()
	if err == nil {
		out, _ := exec.Command("codesign", "-dv", exe).CombinedOutput()
		s := string(out)
		if strings.Contains(s, "com.apple.developer.endpoint-security.client") {
			fmt.Fprintln(w, "codesign: endpoint-security.client entitlement present")
		} else {
			fmt.Fprintln(w, "codesign: no endpoint-security.client in codesign -dv output (dev build?)")
		}
	}
	fmt.Fprintln(w, "TCC: root does not grant Full Disk Access; use System Settings or MDM PPPC if paths are empty.")
	if n := len(cfg.Monitoring.ESFMutePathPrefixes); n > 0 {
		fmt.Fprintf(w, "config esf_mute_path_prefixes: %d extra prefix(es)\n", n)
	}
}

func printWindows(w io.Writer, cfg config.Config) {
	fmt.Fprintln(w, "Run as elevated Windows Service (Local System) for ETW kernel providers.")
	fmt.Fprintln(w, "Minifilter/WFP: not loaded (tier-2 driver roadmap).")
	m := cfg.Monitoring
	fmt.Fprintf(w, "optional ETW flags: wmi=%v ps=%v pipes=%v bits=%v tasks=%v\n",
		m.ETWWMIActivity, m.ETWPowerShellScript, m.ETWNamedPipeHandles, m.ETWBitsClient, m.ETWTaskScheduler)
}

func printMonitoringHealthFile(w io.Writer, cfg config.Config) {
	if cfg.Agent.DataDir == "" {
		fmt.Fprintln(w, "monitoring health: (no agent data_dir)")
		return
	}
	p := filepath.Join(cfg.Agent.DataDir, "monitoring_health.json")
	data, err := os.ReadFile(p)
	if err != nil {
		fmt.Fprintf(w, "monitoring health: %s not readable (%v); enable health_snapshot_sec on a running agent\n", p, err)
		return
	}
	fmt.Fprintf(w, "monitoring health: %s\n", p)
	var snap map[string]interface{}
	if err := json.Unmarshal(data, &snap); err != nil {
		fmt.Fprintf(w, "  (invalid json: %v)\n", err)
		return
	}
	if k, ok := snap["kernel"].(map[string]interface{}); ok {
		fmt.Fprintf(w, "  kernel keys: %v\n", keysOf(k))
	}
}

func keysOf(m map[string]interface{}) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
