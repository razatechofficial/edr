package collector

import (
	"bufio"
	"context"
	"bytes"
	"math"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/razatechofficial/edr/internal/config"
	"github.com/razatechofficial/edr/internal/schema"
)

// DNSCollector monitors DNS query logs to capture domain resolution events.
// On Linux it may tail syslog files or follow journald systemd-resolved.
type DNSCollector struct {
	endpointID string
	hostname   string
	logPath    string
	sourceKind string // "syslog_tail" | "journal_systemd" | "unconfigured" | "unsupported_goos"
	mu         sync.Mutex
	events     []Telemetry
	cancel     context.CancelFunc
	seen       map[string]time.Time

	emitted atomic.Uint64
	dropped atomic.Uint64

	rareProbes  []string
	rareWinning string
}

func NewDNSCollector(endpointID string, cfg config.Config) *DNSCollector {
	hostname, _ := os.Hostname()
	base := &DNSCollector{
		endpointID: endpointID,
		hostname:   hostname,
		seen:       make(map[string]time.Time),
	}
	if cfg.Monitoring.DnsJournalSystemd && runtime.GOOS == "linux" && systemdJournalEligible() && journalctlBinPresent() {
		base.logPath = "journal://systemd-resolved"
		base.sourceKind = "journal_systemd"
		return base
	}
	if logPath := dnsLogPath(cfg); logPath != "" {
		base.logPath = logPath
		base.sourceKind = "syslog_tail"
		return base
	}
	// Linux/macOS: always attach a DNS collector so health explains absence (no silent nil).
	if runtime.GOOS == "linux" || runtime.GOOS == "darwin" {
		base.sourceKind = "unconfigured"
		return base
	}
	// Rare GOOS: use a full probe ladder (file tail, then command poll) before degrading.
	if runtime.GOOS != "windows" {
		path, probes, winner := probeRareDNSSource(cfg.Monitoring.DarwinDNSExtraLogPaths)
		base.rareProbes = probes
		base.rareWinning = winner
		if path != "" {
			base.logPath = path
			base.sourceKind = "syslog_tail"
			return base
		}
		if winner == "command_poll" {
			base.sourceKind = "command_poll"
			return base
		}
		base.sourceKind = "unconfigured"
		return base
	}
	return nil
}

func systemdJournalEligible() bool {
	if _, err := os.Stat("/run/systemd/journal/socket"); err != nil {
		return false
	}
	return true
}

func journalctlBinPresent() bool {
	_, err := exec.LookPath("journalctl")
	return err == nil
}

func dnsLogPath(cfg config.Config) string {
	switch runtime.GOOS {
	case "linux":
		for _, p := range []string{"/var/log/syslog", "/var/log/messages"} {
			if _, err := os.Stat(p); err == nil {
				return p
			}
		}
	case "darwin":
		paths := append([]string{}, cfg.Monitoring.DarwinDNSExtraLogPaths...)
		paths = append(paths, "/var/log/system.log", "/private/var/log/system.log")
		for _, p := range paths {
			p = strings.TrimSpace(p)
			if p == "" {
				continue
			}
			if _, err := os.Stat(p); err == nil {
				return p
			}
		}
	}
	return ""
}

func (dc *DNSCollector) Name() string { return "dns" }

func (dc *DNSCollector) Collect(_ context.Context) ([]Telemetry, error) {
	dc.mu.Lock()
	batch := dc.events
	dc.events = nil
	dc.mu.Unlock()
	dc.emitted.Add(uint64(len(batch)))
	return batch, nil
}

// ExportMonitoringHealth surfaces DNS log tailing stats.
func (dc *DNSCollector) ExportMonitoringHealth() map[string]any {
	out := dc.emitted.Load()
	dropped := dc.dropped.Load()
	switch dc.sourceKind {
	case "command_poll":
		src := MonitoringSource{
			Name:    "dns",
			OS:      runtime.GOOS,
			Source:  "rare_command_dns_poll",
			Status:  "healthy",
			EPSOut:  out,
			Dropped: dropped,
		}.ToMap()
		src["probes_attempted"] = append([]string(nil), dc.rareProbes...)
		src["winning_probe"] = dc.rareWinning
		return src
	case "unconfigured":
		last := "no DNS syslog path found; enable monitoring.dns_journal_systemd (Linux) or provide resolvable syslog paths"
		if runtime.GOOS == "darwin" {
			last = "no DNS syslog paths; use monitoring.darwin_unified_log_dns / darwin_log_stream_dns_alt or darwin_dns_extra_log_paths"
		} else if runtime.GOOS != "linux" {
			last = "no DNS source configured for this GOOS; configure log tail paths or platform DNS source"
		}
		return MonitoringSource{
			Name:      "dns",
			OS:        runtime.GOOS,
			Source:    "resolver_fallback",
			Status:    "degraded",
			LastError: last,
			EPSOut:    out,
			Dropped:   dropped,
		}.ToMap()
	case "journal_systemd":
		return MonitoringSource{
			Name:    "dns",
			OS:      runtime.GOOS,
			Source:  "journal_systemd_dns",
			Status:  "healthy",
			EPSOut:  out,
			Dropped: dropped,
		}.ToMap()
	default:
		src := MonitoringSource{
			Name:    "dns",
			OS:      runtime.GOOS,
			Source:  "syslog_tail",
			Status:  "healthy",
			EPSOut:  out,
			Dropped: dropped,
			Notes:   dc.logPath,
		}
		if dc.logPath == "" {
			src.Status = "unavailable"
			src.LastError = "no DNS log path"
		}
		return src.ToMap()
	}
}

func (dc *DNSCollector) Start(ctx context.Context) error {
	if dc.sourceKind == "unconfigured" || dc.sourceKind == "unsupported_goos" {
		return nil
	}
	ctx, dc.cancel = context.WithCancel(ctx)
	switch dc.sourceKind {
	case "journal_systemd":
		go dc.journalTailLoop(ctx)
	case "command_poll":
		go dc.rareCommandPollLoop(ctx)
	default:
		if dc.logPath == "" {
			return nil
		}
		go dc.tailLoop(ctx)
	}
	return nil
}

func (dc *DNSCollector) rareCommandPollLoop(ctx context.Context) {
	t := time.NewTicker(2 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			lines := runRareDNSProbeCommand(ctx)
			if len(lines) == 0 {
				continue
			}
			for _, line := range lines {
				if ev, ok := dc.parseDNSLine(line); ok {
					dc.mu.Lock()
					dc.events = append(dc.events, ev)
					dc.mu.Unlock()
				}
			}
		}
	}
}

func runRareDNSProbeCommand(ctx context.Context) []string {
	cmd := exec.CommandContext(ctx, "sh", "-c", "journalctl -n 200 --no-pager 2>/dev/null || tail -n 200 /var/log/messages /var/log/syslog 2>/dev/null")
	out, err := cmd.Output()
	if err != nil || len(out) == 0 {
		return nil
	}
	if len(out) > 256*1024 {
		out = out[:256*1024]
	}
	raw := bytes.Split(out, []byte{'\n'})
	lines := make([]string, 0, len(raw))
	for _, b := range raw {
		s := strings.TrimSpace(string(b))
		if s != "" {
			lines = append(lines, s)
		}
	}
	return lines
}

func (dc *DNSCollector) journalTailLoop(ctx context.Context) {
	args := []string{"--follow", "--output=cat", "--no-pager", "--unit=systemd-resolved.service"}
	cmd := exec.CommandContext(ctx, "journalctl", args...)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return
	}
	if err := cmd.Start(); err != nil {
		return
	}
	scanner := bufio.NewScanner(stdout)
	scanner.Buffer(make([]byte, 4096), 512*1024)
	for scanner.Scan() {
		if ctx.Err() != nil {
			break
		}
		if ev, ok := dc.parseDNSLine(scanner.Text()); ok {
			dc.mu.Lock()
			dc.events = append(dc.events, ev)
			dc.mu.Unlock()
		}
	}
	_ = stdout.Close()
	_ = cmd.Wait()
}

func (dc *DNSCollector) Stop() {
	if dc.cancel != nil {
		dc.cancel()
	}
}

func (dc *DNSCollector) tailLoop(ctx context.Context) {
	f, err := os.Open(dc.logPath)
	if err != nil {
		return
	}
	defer f.Close()

	if fi, err := f.Stat(); err == nil {
		f.Seek(fi.Size(), 0)
	}

	scanner := bufio.NewScanner(f)
	for {
		for scanner.Scan() {
			if ctx.Err() != nil {
				return
			}
			line := scanner.Text()
			if ev, ok := dc.parseDNSLine(line); ok {
				dc.mu.Lock()
				dc.events = append(dc.events, ev)
				dc.mu.Unlock()
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(500 * time.Millisecond):
		}
	}
}

func (dc *DNSCollector) parseDNSLine(line string) (Telemetry, bool) {
	lower := strings.ToLower(line)

	var domain string
	if strings.Contains(lower, "query[") {
		parts := strings.SplitN(line, "query[", 2)
		if len(parts) == 2 {
			rest := parts[1]
			if idx := strings.Index(rest, "]"); idx >= 0 {
				rest = rest[idx+1:]
				fields := strings.Fields(rest)
				if len(fields) > 0 {
					domain = strings.TrimRight(fields[0], ".")
				}
			}
		}
	} else if strings.Contains(lower, "resolved") && strings.Contains(lower, "query") {
		fields := strings.Fields(line)
		for i, f := range fields {
			if strings.EqualFold(f, "query") && i+1 < len(fields) {
				domain = strings.TrimRight(fields[i+1], ".")
				break
			}
		}
	}

	if domain == "" {
		return Telemetry{}, false
	}

	now := time.Now().UTC()
	if last, exists := dc.seen[domain]; exists && now.Sub(last) < 30*time.Second {
		dc.dropped.Add(1)
		return Telemetry{}, false
	}
	dc.seen[domain] = now

	ne := &schema.NetworkEvent{
		BaseEvent: schema.BaseEvent{
			SchemaVersion: schema.SchemaVersionV1,
			EventType:     schema.EventNetwork,
			EndpointID:    dc.endpointID,
			Timestamp:     now,
			Hostname:      dc.hostname,
			OS:            runtime.GOOS,
		},
		Protocol: "dns",
		Domain:   domain,
		DestPt:   53,
	}

	return Telemetry{Network: ne}, true
}

func isDGA(domain string) bool {
	if len(domain) < 10 {
		return false
	}
	parts := strings.Split(domain, ".")
	if len(parts) < 2 {
		return false
	}
	label := parts[0]
	if len(label) < 12 {
		return false
	}

	var consonants, digits int
	for _, c := range label {
		switch {
		case c >= '0' && c <= '9':
			digits++
		case c == 'b' || c == 'c' || c == 'd' || c == 'f' || c == 'g' || c == 'h' ||
			c == 'j' || c == 'k' || c == 'l' || c == 'm' || c == 'n' || c == 'p' ||
			c == 'q' || c == 'r' || c == 's' || c == 't' || c == 'v' || c == 'w' ||
			c == 'x' || c == 'y' || c == 'z':
			consonants++
		}
	}

	entropy := shannonEntropy(label)
	ratio := float64(consonants+digits) / float64(len(label))
	return entropy > 3.5 && ratio > 0.7
}

func shannonEntropy(s string) float64 {
	freq := make(map[rune]int)
	for _, c := range s {
		freq[c]++
	}
	var entropy float64
	n := float64(len(s))
	for _, count := range freq {
		p := float64(count) / n
		if p > 0 {
			entropy -= p * math.Log2(p)
		}
	}
	return entropy
}
