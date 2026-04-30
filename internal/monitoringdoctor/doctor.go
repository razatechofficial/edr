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
	if _, err := exec.LookPath("journalctl"); err == nil {
		fmt.Fprintln(w, "journalctl: present")
	} else {
		fmt.Fprintln(w, "journalctl: not found in PATH")
	}
	requireSources(w, cfg, expectedHealthSourceNames(cfg))
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
	requireSources(w, cfg, expectedHealthSourceNames(cfg))
}

func printWindows(w io.Writer, cfg config.Config) {
	fmt.Fprintln(w, "Run as elevated Windows Service (Local System) for ETW kernel providers.")
	fmt.Fprintln(w, "Minifilter/WFP: not loaded (tier-2 driver roadmap).")
	m := cfg.Monitoring
	fmt.Fprintf(w, "optional ETW flags: wmi=%v ps=%v pipes=%v bits=%v tasks=%v\n",
		m.ETWWMIActivity, m.ETWPowerShellScript, m.ETWNamedPipeHandles, m.ETWBitsClient, m.ETWTaskScheduler)
	requireSources(w, cfg, expectedHealthSourceNames(cfg))
}

// expectedHealthSourceNames aligns doctor checks with cmd/agent validation:
// pillar sources always; registry on Windows; kernel only when config enables
// kernel-tier monitoring (not merely "windows can use ETW").
func expectedHealthSourceNames(cfg config.Config) []string {
	out := []string{"process", "file", "network", "auth"}
	if runtime.GOOS == "windows" {
		out = append(out, "registry")
	}
	if wantKernelTierDoctor(cfg) {
		out = append(out, "kernel")
	}
	return out
}

func wantKernelTierDoctor(cfg config.Config) bool {
	m := cfg.Monitoring
	if m.Mode == "userland" || !m.KernelEnabled {
		return false
	}
	return true
}

// requireSources reads the latest monitoring_health.json snapshot and warns
// when expected per-OS sources are missing or unhealthy. Snapshot freshness
// is reported alongside each missing source so the operator can tell whether
// the agent is running.
func requireSources(w io.Writer, cfg config.Config, expected []string) {
	if cfg.Agent.DataDir == "" {
		return
	}
	p := filepath.Join(cfg.Agent.DataDir, "monitoring_health.json")
	data, err := os.ReadFile(p)
	if err != nil {
		fmt.Fprintf(w, "expected sources: cannot evaluate (no %s)\n", p)
		return
	}
	var snap map[string]interface{}
	if err := json.Unmarshal(data, &snap); err != nil {
		return
	}
	sources, _ := snap["sources"].([]interface{})
	present := map[string]string{}
	for _, raw := range sources {
		src, ok := raw.(map[string]interface{})
		if !ok {
			continue
		}
		name := stringField(src, "name", "")
		if name == "" {
			continue
		}
		present[name] = stringField(src, "status", "")
	}
	for _, want := range expected {
		st, ok := present[want]
		switch {
		case !ok:
			fmt.Fprintf(w, "  source %s: MISSING\n", want)
		case st == "unavailable" || st == "absent":
			fmt.Fprintf(w, "  source %s: %s\n", want, st)
		case st == "degraded":
			fmt.Fprintf(w, "  source %s: %s\n", want, st)
		}
	}
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
	if rt, ok := snap["runtime"].(map[string]interface{}); ok {
		fmt.Fprintf(w, "  runtime: goroutines=%v heap_alloc_mib=%v num_gc=%v\n",
			rt["num_goroutine"], rt["heap_alloc_mib"], rt["num_gc"])
	}
	if sources, ok := snap["sources"].([]interface{}); ok {
		fmt.Fprintf(w, "  sources (%d):\n", len(sources))
		for _, raw := range sources {
			src, ok := raw.(map[string]interface{})
			if !ok {
				continue
			}
			printSourceRow(w, src)
		}
	}
	if k, ok := snap["kernel"].(map[string]interface{}); ok {
		fmt.Fprintf(w, "  kernel keys: %v\n", keysOf(k))
	}
}

// printSourceRow renders a single MonitoringSource row in tabular form so the
// doctor command can be eyeballed without jq. Fields default to "-" when
// missing; numbers are rendered as-is via %v.
func printSourceRow(w io.Writer, src map[string]interface{}) {
	name := stringField(src, "name", "?")
	osName := stringField(src, "os", "?")
	source := stringField(src, "source", "-")
	status := stringField(src, "status", "-")
	notes := stringField(src, "notes", "")
	lastErr := stringField(src, "last_error", "")
	icon := statusIcon(status)
	fmt.Fprintf(w, "    %s %-22s %-8s %-22s %-10s in=%v out=%v drop=%v",
		icon, name, osName, source, status,
		src["eps_in"], src["eps_out"], src["dropped"])
	if notes != "" {
		fmt.Fprintf(w, " notes=%q", notes)
	}
	if lastErr != "" {
		fmt.Fprintf(w, " err=%q", lastErr)
	}
	fmt.Fprintln(w)
}

func stringField(m map[string]interface{}, key, fallback string) string {
	if v, ok := m[key].(string); ok && v != "" {
		return v
	}
	return fallback
}

func statusIcon(status string) string {
	switch strings.ToLower(status) {
	case "healthy":
		return "[OK]"
	case "degraded":
		return "[WARN]"
	case "standby":
		return "[STBY]"
	case "unavailable", "absent":
		return "[OFF]"
	default:
		return "[?]"
	}
}

func keysOf(m map[string]interface{}) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
