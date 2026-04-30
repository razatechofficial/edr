package collector

import (
	"bufio"
	"context"
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
	sourceKind string // "syslog_tail" | "journal_systemd"
	mu         sync.Mutex
	events     []Telemetry
	cancel     context.CancelFunc
	seen       map[string]time.Time

	emitted atomic.Uint64
	dropped atomic.Uint64
}

func NewDNSCollector(endpointID string, cfg config.Config) *DNSCollector {
	hostname, _ := os.Hostname()
	if cfg.Monitoring.DnsJournalSystemd && runtime.GOOS == "linux" && systemdJournalEligible() && journalctlBinPresent() {
		return &DNSCollector{
			endpointID: endpointID,
			hostname:   hostname,
			logPath:    "journal://systemd-resolved",
			sourceKind: "journal_systemd",
			seen:       make(map[string]time.Time),
		}
	}
	logPath := dnsLogPath(cfg)
	if logPath == "" {
		return nil
	}
	return &DNSCollector{
		endpointID: endpointID,
		hostname:   hostname,
		logPath:    logPath,
		sourceKind: "syslog_tail",
		seen:       make(map[string]time.Time),
	}
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
	src := MonitoringSource{
		Name:    "dns",
		OS:      runtime.GOOS,
		Status:  "healthy",
		EPSOut:  dc.emitted.Load(),
		Dropped: dc.dropped.Load(),
	}
	switch dc.sourceKind {
	case "journal_systemd":
		src.Source = "journal_systemd_dns"
	default:
		src.Source = "syslog_tail"
	}
	if dc.logPath == "" {
		src.Status = "unavailable"
		src.LastError = "no DNS log path detected"
	}
	return src.ToMap()
}

func (dc *DNSCollector) Start(ctx context.Context) error {
	ctx, dc.cancel = context.WithCancel(ctx)
	switch dc.sourceKind {
	case "journal_systemd":
		go dc.journalTailLoop(ctx)
	default:
		go dc.tailLoop(ctx)
	}
	return nil
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
