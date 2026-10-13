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

	// CompletedAt is when the last stage finished. With Timestamp it bounds the
	// window the bundle describes: artifacts inside one bundle are not
	// simultaneous, and pretending otherwise invites wrong conclusions about
	// what happened before what.
	CompletedAt time.Time `json:"completed_at,omitempty"`
	// CollectionOrder is the order the stages actually ran, most volatile
	// first, recorded so the evidence can show it was ordered rather than
	// leaving a reader to trust that it was.
	CollectionOrder []string `json:"collection_order,omitempty"`
	// Timings is when each stage ran and how long it took.
	Timings []StageTiming `json:"timings,omitempty"`
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
//
// The path lists are kept for anything already reading this bundle, but the
// records are the evidence: a path says a file existed, while a record says how
// large it was, when it was last written and — where it could be read — the
// digest of its contents. By the time a bundle is examined the file itself is
// usually gone, so a path alone leads nowhere.
type FileArtifacts struct {
	RecentFiles    []string `json:"recent_files,omitempty"`
	BrowserHistory []string `json:"browser_history_paths,omitempty"`
	TempFiles      []string `json:"temp_files,omitempty"`
	DownloadFiles  []string `json:"download_files,omitempty"`

	TempRecords     []FileRecord `json:"temp_records,omitempty"`
	DownloadRecords []FileRecord `json:"download_records,omitempty"`
	BrowserRecords  []FileRecord `json:"browser_history_records,omitempty"`
	// ScanNote explains what bounded the scan, so a short list is not mistaken
	// for a quiet host.
	ScanNote string `json:"scan_note,omitempty"`
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
	Services      []string             `json:"services,omitempty"`
	Software      []string             `json:"software,omitempty"`
	StartupItems  []string             `json:"startup_items,omitempty"`
	KernelModules []string             `json:"kernel_modules,omitempty"`
	USBHistory    []string             `json:"usb_history,omitempty"`
	Deep          *DeepArtifactsBundle `json:"deep,omitempty"`
}

// ---------------------------------------------------------------------------
// Collector
// ---------------------------------------------------------------------------

// ArtifactCollector gathers system-wide forensic artifacts. Each artifact
// category is collected by a dedicated sub-collector with platform-specific
// dispatch via runtime.GOOS.
type ArtifactCollector struct {
	logger  *zap.Logger
	deepCfg ForensicsDeepConfig
}

// NewArtifactCollector creates a collector that logs progress to logger.
// When deep is non-nil, optional deep artifact collectors run during system artifact gathering.
func NewArtifactCollector(logger *zap.Logger, deep *ForensicsDeepConfig) *ArtifactCollector {
	ac := &ArtifactCollector{logger: logger}
	if deep != nil {
		ac.deepCfg = *deep
	}
	return ac
}

// CollectAll runs every sub-collector and returns an ArtifactBundle.
// Individual sub-collector failures are recorded in bundle.Errors rather
// than aborting the entire collection.
// stage is one category of artifact, with the order it must be collected in.
//
// The order is the point. RFC 3227, "Guidelines for Evidence Collection and
// Archiving", requires collection in order of volatility: the state that
// disappears fastest is captured first, because anything slower taken ahead of
// it destroys it. This collector previously walked the filesystem before
// reading sockets, which can take seconds to minutes — by the time the network
// state was read, the connection that triggered the detection had closed.
type stage struct {
	name string
	// why records the volatility reasoning with the evidence, so a reader
	// years later can see the collection was ordered deliberately.
	why     string
	collect func(context.Context, *ArtifactBundle)
}

// StageTiming is when one stage ran and how long it took.
//
// Part of the evidence rather than a log line: an analyst comparing two
// artifacts needs to know they were not captured ten minutes apart, and a
// bundle that cannot say when each part was read cannot support that.
type StageTiming struct {
	Stage      string        `json:"stage"`
	StartedAt  time.Time     `json:"started_at"`
	Duration   time.Duration `json:"duration_ns"`
	DurationMS int64         `json:"duration_ms"`
}

// stages lists the collection order, most volatile first.
func (ac *ArtifactCollector) stages() []stage {
	return []stage{
		{
			name: "network",
			why:  "sockets, ARP and DNS caches: a connection can close within seconds of the detection",
			collect: func(ctx context.Context, b *ArtifactBundle) {
				b.Network = ac.collectNetworkArtifacts(ctx)
			},
		},
		{
			name: "process",
			why:  "the process table: a process can exit at any moment, taking its command line and parent with it",
			collect: func(ctx context.Context, b *ArtifactBundle) {
				b.Process = ac.collectProcessArtifacts(ctx)
			},
		},
		{
			name: "auth",
			why:  "active sessions are volatile; the login history behind them is on disk and is not",
			collect: func(ctx context.Context, b *ArtifactBundle) {
				b.Auth = ac.collectAuthArtifacts(ctx)
			},
		},
		{
			name: "system",
			why:  "services, modules and persistence: configuration, which changes slowly",
			collect: func(ctx context.Context, b *ArtifactBundle) {
				b.System = ac.collectSystemArtifacts(ctx)
			},
		},
		{
			name: "file",
			why:  "on-disk artifacts: the least volatile, and the slowest to gather, so it runs last",
			collect: func(ctx context.Context, b *ArtifactBundle) {
				b.File = ac.collectFileArtifacts(ctx)
			},
		},
	}
}

// CollectAll gathers every artifact category in order of volatility.
//
// Sequential, not parallel. Running the stages concurrently would make the
// bundle a blend of several moments and would have them competing for the same
// disk and process table, which is the opposite of what ordering by volatility
// is for.
func (ac *ArtifactCollector) CollectAll(ctx context.Context) (*ArtifactBundle, error) {
	hostname, _ := os.Hostname()
	started := time.Now().UTC()
	bundle := &ArtifactBundle{
		Timestamp: started,
		Hostname:  hostname,
		OS:        runtime.GOOS,
	}

	for _, st := range ac.stages() {
		// A stage that cannot run must not stop the ones after it: a host
		// where the process table is unreadable still has network state worth
		// having, and a partial bundle is far better than none.
		if ctx.Err() != nil {
			bundle.Errors = append(bundle.Errors,
				st.name+": not collected, the collection deadline passed")
			continue
		}
		stageStart := time.Now().UTC()
		func() {
			defer func() {
				if rec := recover(); rec != nil {
					bundle.Errors = append(bundle.Errors,
						fmt.Sprintf("%s: panicked during collection: %v", st.name, rec))
				}
			}()
			st.collect(ctx, bundle)
		}()
		elapsed := time.Since(stageStart)
		bundle.Timings = append(bundle.Timings, StageTiming{
			Stage:      st.name,
			StartedAt:  stageStart,
			Duration:   elapsed,
			DurationMS: elapsed.Milliseconds(),
		})
		ac.logger.Debug("artifact stage collected",
			zap.String("stage", st.name),
			zap.String("volatility", st.why),
			zap.Duration("took", elapsed),
		)
	}

	bundle.CollectionOrder = make([]string, 0, len(bundle.Timings))
	for _, t := range bundle.Timings {
		bundle.CollectionOrder = append(bundle.CollectionOrder, t.Stage)
	}
	bundle.CompletedAt = time.Now().UTC()

	ac.logger.Info("artifact collection complete",
		zap.Int("errors", len(bundle.Errors)),
		zap.Duration("took", bundle.CompletedAt.Sub(started)),
		zap.Strings("order", bundle.CollectionOrder),
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

func (ac *ArtifactCollector) collectFileArtifacts(ctx context.Context) *FileArtifacts {
	fa := &FileArtifacts{}
	limits := DefaultFileScanLimits()
	// One budget for the whole stage, not per directory, so three slow
	// directories cannot add up to a scan that outlasts the incident.
	deadline := time.Now().Add(limits.Budget)

	fa.TempRecords = scanDir(ctx, os.TempDir(), limits, deadline)
	fa.TempFiles = Paths(fa.TempRecords)

	home, _ := os.UserHomeDir()
	if home != "" {
		fa.DownloadRecords = scanDir(ctx, filepath.Join(home, "Downloads"), limits, deadline)
		fa.DownloadFiles = Paths(fa.DownloadRecords)

		for _, bp := range browserHistoryPaths(home) {
			if rec, ok := statFile(ctx, bp, limits, deadline); ok {
				fa.BrowserRecords = append(fa.BrowserRecords, rec)
				fa.BrowserHistory = append(fa.BrowserHistory, rec.Path)
			}
		}
	}

	fa.ScanNote = fmt.Sprintf(
		"newest %d files per directory, hashed up to %d bytes each, within a %s budget",
		limits.MaxFiles, limits.MaxHashBytes, limits.Budget,
	)
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
	if ac.deepCfg.AnyEnabled() {
		ac.collectDeepArtifacts(ctx, sa, ac.deepCfg)
	}
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
