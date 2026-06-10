package detection

import (
	"fmt"
	"math"
	"strings"
	"sync"
	"time"

	"github.com/razatechofficial/edr/pkg/events"
	"go.uber.org/zap"
)

const (
	beaconCVThreshold  = 0.15
	beaconMinSamples   = 5
	dgaEntropyMin      = 3.8
	dgaLabelMinLen     = 6
	maxBeaconEntries   = 10000
	maxBeaconSamples   = 100
	maxDGACacheEntries = 50000
)

type beaconEntry struct {
	times      []time.Time
	alertFired bool
}

// RATDetector identifies remote access trojan behavior through C2 beacon
// interval analysis, DGA domain detection, known dynamic DNS usage, and
// clipboard polling patterns.
type RATDetector struct {
	mu       sync.Mutex
	logger   *zap.Logger
	beacons  map[string]*beaconEntry // "pid:ip:port" → connection timestamps
	dgaCache map[string]bool         // domain → isDGA result
}

// NewRATDetector creates a RATDetector.
func NewRATDetector(logger *zap.Logger) *RATDetector {
	return &RATDetector{
		logger:   logger,
		beacons:  make(map[string]*beaconEntry),
		dgaCache: make(map[string]bool),
	}
}

// Name returns the detector identifier.
func (d *RATDetector) Name() string { return "rat" }

// Analyze evaluates network, process, and DNS events for RAT indicators.
func (d *RATDetector) Analyze(event interface{}, correlator *Correlator) []*events.Alert {
	pid := extractPID(event)
	if pid == 0 {
		return nil
	}

	d.mu.Lock()
	defer d.mu.Unlock()

	var alerts []*events.Alert

	if a := d.checkBeacon(event, pid); a != nil {
		alerts = append(alerts, a)
	}
	if a := d.checkDGA(event, pid); a != nil {
		alerts = append(alerts, a)
	}
	if a := d.checkDDNS(event, pid); a != nil {
		alerts = append(alerts, a)
	}
	if a := d.checkClipboardPolling(event, pid, correlator); a != nil {
		alerts = append(alerts, a)
	}

	return alerts
}

// Reset clears all tracked state.
func (d *RATDetector) Reset() {
	d.mu.Lock()
	d.beacons = make(map[string]*beaconEntry)
	d.dgaCache = make(map[string]bool)
	d.mu.Unlock()
}

// ---------------------------------------------------------------------------
// C2 beacon detection
// ---------------------------------------------------------------------------

func (d *RATDetector) checkBeacon(event interface{}, pid uint32) *events.Alert {
	ip := extractDestIP(event)
	port := extractDestPort(event)
	if ip == "" || port == 0 {
		return nil
	}

	key := fmt.Sprintf("%d:%s:%d", pid, ip, port)
	be := d.beacons[key]
	if be == nil {
		d.pruneBeacons()
		be = &beaconEntry{}
		d.beacons[key] = be
	}

	be.times = append(be.times, extractTimestamp(event))
	if len(be.times) > maxBeaconSamples {
		be.times = be.times[len(be.times)-maxBeaconSamples:]
	}

	if len(be.times) < beaconMinSamples || be.alertFired {
		return nil
	}

	cv := coefficientOfVariation(be.times)
	if cv >= beaconCVThreshold {
		return nil
	}

	be.alertFired = true
	d.logger.Warn("C2 beacon pattern detected",
		zap.Uint32("pid", pid), zap.String("dest", fmt.Sprintf("%s:%d", ip, port)),
		zap.Float64("cv", cv))

	return newAlert(
		"RAT-001", "rat", "C2 beacon pattern detected",
		fmt.Sprintf("PID %d shows regular connection intervals (CV=%.3f) to %s:%d — likely automated C2 beacon",
			pid, cv, ip, port),
		events.SeverityHigh,
		[]events.MITREAttack{
			{TechniqueID: "T1071", TechniqueName: "Application Layer Protocol", TacticID: "TA0011", TacticName: "Command and Control"},
			{TechniqueID: "T1573", TechniqueName: "Encrypted Channel", TacticID: "TA0011", TacticName: "Command and Control"},
		},
		[]string{"rat", "c2_beacon", "action:kill_process", "action:host_isolate"}, event,
	)
}

func coefficientOfVariation(times []time.Time) float64 {
	if len(times) < 3 {
		return 1.0
	}
	intervals := make([]float64, 0, len(times)-1)
	for i := 1; i < len(times); i++ {
		intervals = append(intervals, times[i].Sub(times[i-1]).Seconds())
	}
	var sum float64
	for _, v := range intervals {
		sum += v
	}
	mean := sum / float64(len(intervals))
	if mean < 0.001 {
		return 0
	}
	var sqSum float64
	for _, v := range intervals {
		d := v - mean
		sqSum += d * d
	}
	return math.Sqrt(sqSum/float64(len(intervals))) / mean
}

func (d *RATDetector) pruneBeacons() {
	if len(d.beacons) <= maxBeaconEntries {
		return
	}
	for k := range d.beacons {
		delete(d.beacons, k)
		if len(d.beacons) <= maxBeaconEntries/2 {
			break
		}
	}
}

// ---------------------------------------------------------------------------
// DGA domain detection
// ---------------------------------------------------------------------------

func (d *RATDetector) checkDGA(event interface{}, pid uint32) *events.Alert {
	domain := extractDomain(event)
	if domain == "" {
		return nil
	}

	if cached, ok := d.dgaCache[domain]; ok {
		if !cached {
			return nil
		}
	} else {
		if len(d.dgaCache) > maxDGACacheEntries {
			d.dgaCache = make(map[string]bool)
		}
		result := isDGADomain(domain)
		d.dgaCache[domain] = result
		if !result {
			return nil
		}
	}

	d.logger.Info("DGA domain detected",
		zap.Uint32("pid", pid), zap.String("domain", domain))

	return newAlert(
		"RAT-002", "rat", "DGA domain detected",
		fmt.Sprintf("PID %d connected to algorithmically generated domain: %s", pid, domain),
		events.SeverityMedium,
		[]events.MITREAttack{
			{TechniqueID: "T1568.002", TechniqueName: "Domain Generation Algorithms", TacticID: "TA0011", TacticName: "Command and Control"},
		},
		[]string{"rat", "dga"}, event,
	)
}

func isDGADomain(domain string) bool {
	label := getDomainLabel(domain)
	if len(label) < dgaLabelMinLen {
		return false
	}

	ent := shannonEntropy([]byte(label))

	var vowels, consonants, digits int
	for _, c := range strings.ToLower(label) {
		switch {
		case c == 'a' || c == 'e' || c == 'i' || c == 'o' || c == 'u':
			vowels++
		case c >= 'a' && c <= 'z':
			consonants++
		case c >= '0' && c <= '9':
			digits++
		}
	}

	totalAlpha := vowels + consonants
	if totalAlpha == 0 {
		return false
	}
	consonantRatio := float64(consonants) / float64(totalAlpha)
	digitRatio := float64(digits) / float64(len(label))

	if ent > dgaEntropyMin && consonantRatio > 0.7 {
		return true
	}
	if ent > 4.2 {
		return true
	}
	if len(label) > 20 && ent > 3.5 {
		return true
	}
	if digitRatio > 0.3 && ent > 3.5 {
		return true
	}
	return false
}

func getDomainLabel(domain string) string {
	parts := strings.Split(strings.TrimSuffix(domain, "."), ".")
	if len(parts) >= 2 {
		return parts[len(parts)-2]
	}
	if len(parts) == 1 {
		return parts[0]
	}
	return domain
}

// ---------------------------------------------------------------------------
// Dynamic DNS detection
// ---------------------------------------------------------------------------

var knownDDNSProviders = []string{
	"no-ip.com", "no-ip.org", "dyndns.org", "dyndns.com",
	"duckdns.org", "afraid.org", "hopto.org", "zapto.org",
	"sytes.net", "ddns.net", "dynu.com", "freedns.afraid.org",
	"serveftp.com", "servegame.com", "servehttp.com",
	"redirectme.net", "serveblog.net", "chickenkiller.com",
}

func (d *RATDetector) checkDDNS(event interface{}, pid uint32) *events.Alert {
	domain := strings.ToLower(extractDomain(event))
	if domain == "" {
		return nil
	}
	for _, ddns := range knownDDNSProviders {
		if strings.HasSuffix(domain, ddns) {
			d.logger.Info("dynamic DNS domain detected",
				zap.Uint32("pid", pid), zap.String("domain", domain))
			return newAlert(
				"RAT-003", "rat", "Dynamic DNS domain connection",
				fmt.Sprintf("PID %d connected to dynamic DNS domain: %s", pid, domain),
				events.SeverityMedium,
				[]events.MITREAttack{
					{TechniqueID: "T1568.001", TechniqueName: "Fast Flux DNS", TacticID: "TA0011", TacticName: "Command and Control"},
				},
				[]string{"rat", "ddns"}, event,
			)
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// Clipboard polling detection
// ---------------------------------------------------------------------------

func (d *RATDetector) checkClipboardPolling(event interface{}, pid uint32, correlator *Correlator) *events.Alert {
	cmd := strings.ToLower(extractCommandLine(event))
	if !containsAny(cmd, "get-clipboard", "xclip", "xsel", "pbpaste", "clipboard") {
		return nil
	}

	recent := correlator.GetProcessEvents(pid, Window5m)
	clipCount := 0
	for _, ev := range recent {
		if containsAny(strings.ToLower(extractCommandLine(ev)), "get-clipboard", "xclip", "xsel", "pbpaste", "clipboard") {
			clipCount++
		}
	}
	if clipCount < 5 {
		return nil
	}

	return newAlert(
		"RAT-004", "rat", "Clipboard polling detected",
		fmt.Sprintf("PID %d accessed clipboard %d times in 5 minutes — possible data theft", pid, clipCount),
		events.SeverityMedium,
		[]events.MITREAttack{
			{TechniqueID: "T1115", TechniqueName: "Clipboard Data", TacticID: "TA0009", TacticName: "Collection"},
		},
		[]string{"rat", "clipboard"}, event,
	)
}
