package forensics

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"go.uber.org/zap"
)

// ---------------------------------------------------------------------------
// Artifact types
// ---------------------------------------------------------------------------

// ArtifactBundle is the top-level container returned by a full forensic
// artifact collection pass.
type ArtifactBundle struct {
	Timestamp time.Time         `json:"timestamp"`
	Hostname  string            `json:"hostname"`
	OS        string            `json:"os"`
	Process   *ProcessArtifacts `json:"process,omitempty"`
	File      *FileArtifacts    `json:"file,omitempty"`
	Network   *NetworkArtifacts `json:"network,omitempty"`
	Auth      *AuthArtifacts    `json:"auth,omitempty"`
	System    *SystemArtifacts  `json:"system,omitempty"`
	Errors    []string          `json:"errors,omitempty"`
}

// ProcessArtifacts contains process tree, handles, connections, and modules.
type ProcessArtifacts struct {
	Processes   []ProcessInfo `json:"processes"`
	Environment []string      `json:"environment,omitempty"`
}

// ProcessInfo describes a single running process.
type ProcessInfo struct {
	PID         int    `json:"pid"`
	PPID        int    `json:"ppid"`
	Name        string `json:"name"`
	User        string `json:"user"`
	CommandLine string `json:"command_line"`
}

// FileArtifacts contains filesystem evidence.
type FileArtifacts struct {
	RecentFiles    []string `json:"recent_files,omitempty"`
	BrowserHistory []string `json:"browser_history_paths,omitempty"`
	TempFiles      []string `json:"temp_files,omitempty"`
	DownloadFiles  []string `json:"download_files,omitempty"`
}

// NetworkArtifacts contains networking evidence.
type NetworkArtifacts struct {
	Connections []ConnectionInfo `json:"connections"`
	DNSCache    []string         `json:"dns_cache,omitempty"`
	ARPTable    []string         `json:"arp_table,omitempty"`
	Routes      []string         `json:"routes,omitempty"`
	HostsFile   string           `json:"hosts_file,omitempty"`
}

// ConnectionInfo describes one network socket.
type ConnectionInfo struct {
	Protocol   string `json:"protocol"`
	LocalAddr  string `json:"local_addr"`
	RemoteAddr string `json:"remote_addr"`
	State      string `json:"state"`
	PID        int    `json:"pid,omitempty"`
}

// AuthArtifacts contains authentication and authorization evidence.
type AuthArtifacts struct {
	RecentLogins   []string `json:"recent_logins,omitempty"`
	ActiveSessions []string `json:"active_sessions,omitempty"`
	SudoHistory    []string `json:"sudo_history,omitempty"`
}

// SystemArtifacts contains system configuration evidence.
type SystemArtifacts struct {
	Services      []string `json:"services,omitempty"`
	Software      []string `json:"software,omitempty"`
	StartupItems  []string `json:"startup_items,omitempty"`
	KernelModules []string `json:"kernel_modules,omitempty"`
	USBHistory    []string `json:"usb_history,omitempty"`
}

// ---------------------------------------------------------------------------
// Collector
// ---------------------------------------------------------------------------

// ArtifactCollector gathers system-wide forensic artifacts. Each artifact
// category is collected by a dedicated sub-collector with platform-specific
// dispatch via runtime.GOOS.
type ArtifactCollector struct {
	logger *zap.Logger
}

// NewArtifactCollector creates a collector that logs progress to logger.
func NewArtifactCollector(logger *zap.Logger) *ArtifactCollector {
	return &ArtifactCollector{logger: logger}
}

// CollectAll runs every sub-collector and returns an ArtifactBundle.
// Individual sub-collector failures are recorded in bundle.Errors rather
// than aborting the entire collection.
func (ac *ArtifactCollector) CollectAll(ctx context.Context) (*ArtifactBundle, error) {
	hostname, _ := os.Hostname()
	bundle := &ArtifactBundle{
		Timestamp: time.Now().UTC(),
		Hostname:  hostname,
		OS:        runtime.GOOS,
	}

	type result struct {
		name string
		err  error
	}

	collect := func(name string, fn func(context.Context) error) result {
		if err := fn(ctx); err != nil {
			return result{name, err}
		}
		return result{name, nil}
	}

	r := collect("process", func(ctx context.Context) error {
		bundle.Process = ac.collectProcessArtifacts(ctx)
		return nil
	})
	if r.err != nil {
		bundle.Errors = append(bundle.Errors, r.name+": "+r.err.Error())
	}

	r = collect("file", func(ctx context.Context) error {
		bundle.File = ac.collectFileArtifacts(ctx)
		return nil
	})
	if r.err != nil {
		bundle.Errors = append(bundle.Errors, r.name+": "+r.err.Error())
	}

	r = collect("network", func(ctx context.Context) error {
		bundle.Network = ac.collectNetworkArtifacts(ctx)
		return nil
	})
	if r.err != nil {
		bundle.Errors = append(bundle.Errors, r.name+": "+r.err.Error())
	}

	r = collect("auth", func(ctx context.Context) error {
		bundle.Auth = ac.collectAuthArtifacts(ctx)
		return nil
	})
	if r.err != nil {
		bundle.Errors = append(bundle.Errors, r.name+": "+r.err.Error())
	}

	r = collect("system", func(ctx context.Context) error {
		bundle.System = ac.collectSystemArtifacts(ctx)
		return nil
	})
	if r.err != nil {
		bundle.Errors = append(bundle.Errors, r.name+": "+r.err.Error())
	}

	ac.logger.Info("artifact collection complete",
		zap.Int("errors", len(bundle.Errors)),
	)
	return bundle, nil
}

// ---------------------------------------------------------------------------
// Process artifacts
// ---------------------------------------------------------------------------

func (ac *ArtifactCollector) collectProcessArtifacts(ctx context.Context) *ProcessArtifacts {
	pa := &ProcessArtifacts{
		Environment: os.Environ(),
	}
	switch runtime.GOOS {
	case "linux":
		pa.Processes = ac.collectProcessesLinux()
	default:
		pa.Processes = ac.collectProcessesCmd(ctx)
	}
	return pa
}

func (ac *ArtifactCollector) collectProcessesLinux() []ProcessInfo {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil
	}
	var procs []ProcessInfo
	for _, e := range entries {
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		pi := ProcessInfo{PID: pid}
		if data, err := os.ReadFile(fmt.Sprintf("/proc/%d/comm", pid)); err == nil {
			pi.Name = strings.TrimSpace(string(data))
		}
		if data, err := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid)); err == nil {
			pi.CommandLine = strings.ReplaceAll(string(data), "\x00", " ")
		}
		if data, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid)); err == nil {
			for _, line := range strings.Split(string(data), "\n") {
				if strings.HasPrefix(line, "PPid:") {
					pi.PPID, _ = strconv.Atoi(strings.TrimSpace(strings.TrimPrefix(line, "PPid:")))
				}
				if strings.HasPrefix(line, "Uid:") {
					fields := strings.Fields(line)
					if len(fields) >= 2 {
						pi.User = fields[1]
					}
				}
			}
		}
		procs = append(procs, pi)
	}
	return procs
}

func (ac *ArtifactCollector) collectProcessesCmd(ctx context.Context) []ProcessInfo {
	out := runCmd(ctx, "ps", "axo", "pid,ppid,user,comm")
	if out == "" {
		return nil
	}
	var procs []ProcessInfo
	for i, line := range strings.Split(out, "\n") {
		if i == 0 || strings.TrimSpace(line) == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}
		pid, _ := strconv.Atoi(fields[0])
		ppid, _ := strconv.Atoi(fields[1])
		procs = append(procs, ProcessInfo{
			PID:  pid,
			PPID: ppid,
			User: fields[2],
			Name: strings.Join(fields[3:], " "),
		})
	}
	return procs
}

// ---------------------------------------------------------------------------
// File artifacts
// ---------------------------------------------------------------------------

func (ac *ArtifactCollector) collectFileArtifacts(_ context.Context) *FileArtifacts {
	fa := &FileArtifacts{}
	fa.TempFiles = listDir(os.TempDir(), 200)

	home, _ := os.UserHomeDir()
	if home != "" {
		dlDir := filepath.Join(home, "Downloads")
		fa.DownloadFiles = listDir(dlDir, 200)

		for _, bp := range browserHistoryPaths(home) {
			if _, err := os.Stat(bp); err == nil {
				fa.BrowserHistory = append(fa.BrowserHistory, bp)
			}
		}
	}
	return fa
}

func browserHistoryPaths(home string) []string {
	switch runtime.GOOS {
	case "linux":
		return []string{
			filepath.Join(home, ".config/google-chrome/Default/History"),
			filepath.Join(home, ".mozilla/firefox"),
		}
	case "darwin":
		return []string{
			filepath.Join(home, "Library/Application Support/Google/Chrome/Default/History"),
			filepath.Join(home, "Library/Safari/History.db"),
		}
	case "windows":
		localAppData := os.Getenv("LOCALAPPDATA")
		return []string{
			filepath.Join(localAppData, "Google", "Chrome", "User Data", "Default", "History"),
			filepath.Join(localAppData, "Microsoft", "Edge", "User Data", "Default", "History"),
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// Network artifacts
// ---------------------------------------------------------------------------

func (ac *ArtifactCollector) collectNetworkArtifacts(ctx context.Context) *NetworkArtifacts {
	na := &NetworkArtifacts{}

	switch runtime.GOOS {
	case "linux":
		na.Connections = parseProcNet("/proc/net/tcp", "tcp")
		na.Connections = append(na.Connections, parseProcNet("/proc/net/udp", "udp")...)
	default:
		na.Connections = parseNetstatOutput(ctx)
	}

	if data, err := os.ReadFile("/etc/hosts"); err == nil {
		na.HostsFile = string(data)
	}
	if out := runCmd(ctx, "arp", "-a"); out != "" {
		na.ARPTable = strings.Split(strings.TrimSpace(out), "\n")
	}
	switch runtime.GOOS {
	case "linux":
		if out := runCmd(ctx, "ip", "route"); out != "" {
			na.Routes = strings.Split(strings.TrimSpace(out), "\n")
		}
	default:
		if out := runCmd(ctx, "netstat", "-rn"); out != "" {
			na.Routes = strings.Split(strings.TrimSpace(out), "\n")
		}
	}
	return na
}

func parseProcNet(path, proto string) []ConnectionInfo {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	var conns []ConnectionInfo
	scanner := bufio.NewScanner(f)
	first := true
	for scanner.Scan() {
		if first {
			first = false
			continue
		}
		fields := strings.Fields(scanner.Text())
		if len(fields) < 4 {
			continue
		}
		conns = append(conns, ConnectionInfo{
			Protocol:   proto,
			LocalAddr:  decodeHexAddr(fields[1]),
			RemoteAddr: decodeHexAddr(fields[2]),
			State:      decodeTCPState(fields[3]),
		})
	}
	return conns
}

func parseNetstatOutput(ctx context.Context) []ConnectionInfo {
	var args []string
	switch runtime.GOOS {
	case "darwin":
		args = []string{"-an", "-p", "tcp"}
	case "windows":
		args = []string{"-ano"}
	default:
		args = []string{"-tulnp"}
	}
	out := runCmd(ctx, "netstat", args...)
	if out == "" {
		return nil
	}
	var conns []ConnectionInfo
	for _, line := range strings.Split(out, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}
		proto := strings.ToLower(fields[0])
		if !strings.HasPrefix(proto, "tcp") && !strings.HasPrefix(proto, "udp") {
			continue
		}
		ci := ConnectionInfo{Protocol: proto}
		if len(fields) >= 4 {
			ci.LocalAddr = fields[3]
		}
		if len(fields) >= 5 {
			ci.RemoteAddr = fields[4]
		}
		if len(fields) >= 6 {
			ci.State = fields[5]
		}
		conns = append(conns, ci)
	}
	return conns
}

// ---------------------------------------------------------------------------
// Auth artifacts
// ---------------------------------------------------------------------------

func (ac *ArtifactCollector) collectAuthArtifacts(ctx context.Context) *AuthArtifacts {
	aa := &AuthArtifacts{}

	if out := runCmd(ctx, "last", "-20"); out != "" {
		aa.RecentLogins = strings.Split(strings.TrimSpace(out), "\n")
	}
	if out := runCmd(ctx, "who"); out != "" {
		aa.ActiveSessions = strings.Split(strings.TrimSpace(out), "\n")
	}

	switch runtime.GOOS {
	case "linux":
		if data, err := os.ReadFile("/var/log/auth.log"); err == nil {
			lines := strings.Split(string(data), "\n")
			var sudo []string
			for _, l := range lines {
				if strings.Contains(l, "sudo") {
					sudo = append(sudo, l)
				}
			}
			if len(sudo) > 100 {
				sudo = sudo[len(sudo)-100:]
			}
			aa.SudoHistory = sudo
		}
	case "darwin":
		if out := runCmd(ctx, "log", "show", "--predicate",
			"process == \"sudo\"", "--last", "1h", "--style", "compact"); out != "" {
			lines := strings.Split(strings.TrimSpace(out), "\n")
			if len(lines) > 100 {
				lines = lines[len(lines)-100:]
			}
			aa.SudoHistory = lines
		}
	}
	return aa
}

// ---------------------------------------------------------------------------
// System artifacts
// ---------------------------------------------------------------------------

func (ac *ArtifactCollector) collectSystemArtifacts(ctx context.Context) *SystemArtifacts {
	sa := &SystemArtifacts{}

	switch runtime.GOOS {
	case "linux":
		if out := runCmd(ctx, "systemctl", "list-units", "--type=service", "--no-pager", "--plain"); out != "" {
			sa.Services = strings.Split(strings.TrimSpace(out), "\n")
		}
		if data, err := os.ReadFile("/proc/modules"); err == nil {
			sa.KernelModules = strings.Split(strings.TrimSpace(string(data)), "\n")
		}
		if out := runCmd(ctx, "dpkg", "-l"); out != "" {
			sa.Software = strings.Split(strings.TrimSpace(out), "\n")
		} else if out := runCmd(ctx, "rpm", "-qa"); out != "" {
			sa.Software = strings.Split(strings.TrimSpace(out), "\n")
		}
		sa.StartupItems = collectLinuxStartup()
	case "darwin":
		if out := runCmd(ctx, "launchctl", "list"); out != "" {
			sa.Services = strings.Split(strings.TrimSpace(out), "\n")
		}
		if out := runCmd(ctx, "kextstat"); out != "" {
			sa.KernelModules = strings.Split(strings.TrimSpace(out), "\n")
		}
		if out := runCmd(ctx, "system_profiler", "SPApplicationsDataType", "-detailLevel", "mini"); out != "" {
			sa.Software = strings.Split(strings.TrimSpace(out), "\n")
		}
		sa.StartupItems = collectDarwinStartup()
	case "windows":
		if out := runCmd(ctx, "sc", "query", "type=", "service", "state=", "all"); out != "" {
			sa.Services = strings.Split(strings.TrimSpace(out), "\n")
		}
		if out := runCmd(ctx, "wmic", "product", "get", "name,version"); out != "" {
			sa.Software = strings.Split(strings.TrimSpace(out), "\n")
		}
	}

	sa.USBHistory = collectUSBHistory(ctx)
	return sa
}

func collectLinuxStartup() []string {
	var items []string
	for _, dir := range []string{"/etc/init.d", "/etc/systemd/system"} {
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, e := range entries {
			items = append(items, filepath.Join(dir, e.Name()))
		}
	}
	return items
}

func collectDarwinStartup() []string {
	var items []string
	for _, dir := range []string{
		"/Library/LaunchDaemons",
		"/Library/LaunchAgents",
	} {
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, e := range entries {
			items = append(items, filepath.Join(dir, e.Name()))
		}
	}
	return items
}

func collectUSBHistory(ctx context.Context) []string {
	switch runtime.GOOS {
	case "linux":
		if out := runCmd(ctx, "lsusb"); out != "" {
			return strings.Split(strings.TrimSpace(out), "\n")
		}
	case "darwin":
		if out := runCmd(ctx, "system_profiler", "SPUSBDataType"); out != "" {
			return strings.Split(strings.TrimSpace(out), "\n")
		}
	case "windows":
		if out := runCmd(ctx, "wmic", "path", "Win32_USBControllerDevice", "get", "Dependent"); out != "" {
			return strings.Split(strings.TrimSpace(out), "\n")
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// Utilities
// ---------------------------------------------------------------------------

func runCmd(ctx context.Context, name string, args ...string) string {
	out, err := exec.CommandContext(ctx, name, args...).CombinedOutput()
	if err != nil {
		return ""
	}
	return string(out)
}

func listDir(dir string, max int) []string {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	var names []string
	for i, e := range entries {
		if i >= max {
			break
		}
		names = append(names, filepath.Join(dir, e.Name()))
	}
	return names
}

func decodeHexAddr(s string) string {
	parts := strings.SplitN(s, ":", 2)
	if len(parts) != 2 {
		return s
	}
	ipHex, portHex := parts[0], parts[1]
	port, _ := strconv.ParseUint(portHex, 16, 16)

	if len(ipHex) == 8 {
		a, _ := strconv.ParseUint(ipHex[6:8], 16, 8)
		b, _ := strconv.ParseUint(ipHex[4:6], 16, 8)
		c, _ := strconv.ParseUint(ipHex[2:4], 16, 8)
		d, _ := strconv.ParseUint(ipHex[0:2], 16, 8)
		return fmt.Sprintf("%d.%d.%d.%d:%d", a, b, c, d, port)
	}
	return fmt.Sprintf("%s:%d", ipHex, port)
}

func decodeTCPState(hex string) string {
	states := map[string]string{
		"01": "ESTABLISHED", "02": "SYN_SENT", "03": "SYN_RECV",
		"04": "FIN_WAIT1", "05": "FIN_WAIT2", "06": "TIME_WAIT",
		"07": "CLOSE", "08": "CLOSE_WAIT", "09": "LAST_ACK",
		"0A": "LISTEN", "0B": "CLOSING",
	}
	if s, ok := states[strings.ToUpper(hex)]; ok {
		return s
	}
	return hex
}
