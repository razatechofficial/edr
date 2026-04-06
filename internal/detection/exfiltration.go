package detection

import (
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/razatechofficial/edr/pkg/events"
	"go.uber.org/zap"
)

const (
	dnsQueryRateThreshold     = 100
	dnsSubdomainLenThreshold  = 40
	largeTxnConnThreshold     = 100
	stagingFileThreshold      = 20
	maxDNSTrackerDomains      = 50000
)

type dnsQueryRecord struct {
	times         []time.Time
	maxSubdomLen  int
	alertFired    bool
}

// ExfiltrationDetector identifies data exfiltration through large outbound
// data transfers, DNS tunneling, cloud storage uploads, compression-then-upload
// patterns, and staging directory accumulation.
type ExfiltrationDetector struct {
	mu         sync.Mutex
	logger     *zap.Logger
	dnsRecords map[string]*dnsQueryRecord // base domain → query tracking
}

// NewExfiltrationDetector creates an ExfiltrationDetector.
func NewExfiltrationDetector(logger *zap.Logger) *ExfiltrationDetector {
	return &ExfiltrationDetector{
		logger:     logger,
		dnsRecords: make(map[string]*dnsQueryRecord),
	}
}

// Name returns the detector identifier.
func (d *ExfiltrationDetector) Name() string { return "exfiltration" }

// Analyze evaluates network and file events for exfiltration indicators.
func (d *ExfiltrationDetector) Analyze(event interface{}, correlator *Correlator) []*events.Alert {
	pid := extractPID(event)
	if pid == 0 {
		return nil
	}

	var alerts []*events.Alert
	if a := d.checkLargeTransfer(event, pid, correlator); a != nil {
		alerts = append(alerts, a)
	}
	if a := d.checkDNSTunneling(event, pid); a != nil {
		alerts = append(alerts, a)
	}
	if a := d.checkCloudStorage(event, pid); a != nil {
		alerts = append(alerts, a)
	}
	if a := d.checkCompressThenUpload(event, pid, correlator); a != nil {
		alerts = append(alerts, a)
	}
	if a := d.checkStagingDir(event, pid, correlator); a != nil {
		alerts = append(alerts, a)
	}
	return alerts
}

// Reset clears all tracked state.
func (d *ExfiltrationDetector) Reset() {
	d.mu.Lock()
	d.dnsRecords = make(map[string]*dnsQueryRecord)
	d.mu.Unlock()
}

// ---------------------------------------------------------------------------
// Large outbound data transfer
// ---------------------------------------------------------------------------

func (d *ExfiltrationDetector) checkLargeTransfer(event interface{}, pid uint32, correlator *Correlator) *events.Alert {
	ip := extractDestIP(event)
	if ip == "" {
		return nil
	}

	conns := correlator.GetRecentConnections(pid, Window1h)
	if len(conns) < largeTxnConnThreshold {
		return nil
	}

	d.logger.Warn("high-volume outbound connections",
		zap.Uint32("pid", pid), zap.Int("connections", len(conns)))
	return newAlert(
		"EXFIL-001", "exfiltration", "Large outbound data transfer",
		fmt.Sprintf("PID %d made %d unique outbound connections in 1 hour — possible data exfiltration",
			pid, len(conns)),
		events.SeverityHigh,
		[]events.MITREAttack{
			{TechniqueID: "T1041", TechniqueName: "Exfiltration Over C2 Channel", TacticID: "TA0010", TacticName: "Exfiltration"},
		},
		[]string{"exfiltration", "large_transfer", "action:host_isolate"}, event,
	)
}

// ---------------------------------------------------------------------------
// DNS tunneling
// ---------------------------------------------------------------------------

func (d *ExfiltrationDetector) checkDNSTunneling(event interface{}, pid uint32) *events.Alert {
	domain := extractDomain(event)
	port := extractDestPort(event)
	if domain == "" || (port != 53 && port != 0) {
		return nil
	}

	base := getBaseDomain(domain)
	subdomain := getSubdomain(domain, base)

	d.mu.Lock()
	defer d.mu.Unlock()

	rec := d.dnsRecords[base]
	if rec == nil {
		if len(d.dnsRecords) > maxDNSTrackerDomains {
			d.dnsRecords = make(map[string]*dnsQueryRecord)
		}
		rec = &dnsQueryRecord{}
		d.dnsRecords[base] = rec
	}

	now := time.Now()
	rec.times = append(rec.times, now)
	if len(subdomain) > rec.maxSubdomLen {
		rec.maxSubdomLen = len(subdomain)
	}

	if rec.alertFired {
		return nil
	}

	// Prune queries older than 1 minute
	cutoff := now.Add(-time.Minute)
	n := 0
	for _, t := range rec.times {
		if !t.Before(cutoff) {
			rec.times[n] = t
			n++
		}
	}
	rec.times = rec.times[:n]

	isTunneling := n > dnsQueryRateThreshold || rec.maxSubdomLen > dnsSubdomainLenThreshold

	// Also check subdomain entropy
	if len(subdomain) > 10 && shannonEntropy([]byte(subdomain)) > 3.5 && n > 30 {
		isTunneling = true
	}

	if !isTunneling {
		return nil
	}

	rec.alertFired = true
	d.logger.Warn("DNS tunneling detected",
		zap.Uint32("pid", pid), zap.String("domain", base),
		zap.Int("queries_per_min", n), zap.Int("max_subdomain_len", rec.maxSubdomLen))

	return newAlert(
		"EXFIL-002", "exfiltration", "DNS tunneling detected",
		fmt.Sprintf("PID %d: %d DNS queries/min to %s (max subdomain length %d) — likely DNS tunneling",
			pid, n, base, rec.maxSubdomLen),
		events.SeverityCritical,
		[]events.MITREAttack{
			{TechniqueID: "T1048.003", TechniqueName: "Exfiltration Over Unencrypted Non-C2 Protocol", TacticID: "TA0010", TacticName: "Exfiltration"},
			{TechniqueID: "T1071.004", TechniqueName: "DNS", TacticID: "TA0011", TacticName: "Command and Control"},
		},
		[]string{"exfiltration", "dns_tunneling", "action:kill_process", "action:host_isolate"}, event,
	)
}

func getBaseDomain(domain string) string {
	parts := strings.Split(strings.TrimSuffix(domain, "."), ".")
	if len(parts) >= 2 {
		return parts[len(parts)-2] + "." + parts[len(parts)-1]
	}
	return domain
}

func getSubdomain(domain, base string) string {
	d := strings.TrimSuffix(domain, ".")
	if !strings.HasSuffix(d, base) {
		return ""
	}
	sub := strings.TrimSuffix(d, "."+base)
	if sub == d {
		return ""
	}
	return sub
}

// ---------------------------------------------------------------------------
// Cloud storage upload detection
// ---------------------------------------------------------------------------

var cloudStorageDomains = []string{
	"dropbox.com", "dl.dropboxusercontent.com",
	"drive.google.com", "storage.googleapis.com",
	"onedrive.live.com", "graph.microsoft.com",
	"mega.nz", "mega.co.nz",
	"box.com", "upload.box.com",
	"wetransfer.com", "pastebin.com",
	"transfer.sh", "file.io", "anonfiles.com",
}

func (d *ExfiltrationDetector) checkCloudStorage(event interface{}, pid uint32) *events.Alert {
	domain := strings.ToLower(extractDomain(event))
	if domain == "" {
		return nil
	}

	for _, csd := range cloudStorageDomains {
		if strings.HasSuffix(domain, csd) || domain == csd {
			d.logger.Info("cloud storage connection",
				zap.Uint32("pid", pid), zap.String("domain", domain))
			return newAlert(
				"EXFIL-003", "exfiltration", "Cloud storage upload detected",
				fmt.Sprintf("PID %d connected to cloud storage service: %s", pid, domain),
				events.SeverityMedium,
				[]events.MITREAttack{
					{TechniqueID: "T1567.002", TechniqueName: "Exfiltration to Cloud Storage", TacticID: "TA0010", TacticName: "Exfiltration"},
				},
				[]string{"exfiltration", "cloud_storage"}, event,
			)
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// Compression before upload pattern
// ---------------------------------------------------------------------------

func (d *ExfiltrationDetector) checkCompressThenUpload(event interface{}, pid uint32, correlator *Correlator) *events.Alert {
	domain := extractDomain(event)
	ip := extractDestIP(event)
	if domain == "" && ip == "" {
		return nil
	}

	recentFiles := correlator.GetRecentFiles(pid, Window5m)
	hasCompression := false
	for _, f := range recentFiles {
		fl := strings.ToLower(f)
		if containsAny(fl, ".zip", ".tar", ".gz", ".7z", ".rar", ".bz2") {
			hasCompression = true
			break
		}
	}
	if !hasCompression {
		return nil
	}

	d.logger.Warn("compression before upload",
		zap.Uint32("pid", pid))
	return newAlert(
		"EXFIL-004", "exfiltration", "Compression before network upload",
		fmt.Sprintf("PID %d created compressed archive then initiated network transfer", pid),
		events.SeverityHigh,
		[]events.MITREAttack{
			{TechniqueID: "T1560.001", TechniqueName: "Archive via Utility", TacticID: "TA0009", TacticName: "Collection"},
			{TechniqueID: "T1041", TechniqueName: "Exfiltration Over C2 Channel", TacticID: "TA0010", TacticName: "Exfiltration"},
		},
		[]string{"exfiltration", "compress_upload"}, event,
	)
}

// ---------------------------------------------------------------------------
// Staging directory detection
// ---------------------------------------------------------------------------

var stagingDirPatterns = []string{
	"/tmp/", "\\temp\\", "/var/tmp/", "/dev/shm/",
	"\\appdata\\local\\temp\\",
}

func (d *ExfiltrationDetector) checkStagingDir(event interface{}, pid uint32, correlator *Correlator) *events.Alert {
	path := strings.ToLower(extractFilePath(event))
	op := strings.ToLower(extractFileOperation(event))
	if path == "" || (op != "create" && op != "write") {
		return nil
	}

	if !containsAny(path, stagingDirPatterns...) {
		return nil
	}

	recentFiles := correlator.GetRecentFiles(pid, Window1h)
	tempCount := 0
	for _, f := range recentFiles {
		if containsAny(strings.ToLower(f), stagingDirPatterns...) {
			tempCount++
		}
	}
	if tempCount < stagingFileThreshold {
		return nil
	}

	d.logger.Warn("staging directory accumulation",
		zap.Uint32("pid", pid), zap.Int("temp_files", tempCount))
	return newAlert(
		"EXFIL-005", "exfiltration", "Data staging in temp directory",
		fmt.Sprintf("PID %d accumulated %d files in temp directories — possible exfiltration staging",
			pid, tempCount),
		events.SeverityHigh,
		[]events.MITREAttack{
			{TechniqueID: "T1074.001", TechniqueName: "Local Data Staging", TacticID: "TA0009", TacticName: "Collection"},
		},
		[]string{"exfiltration", "staging"}, event,
	)
}
