package telemetry

import (
	"fmt"
	"net"
	"os/user"
	"strconv"
	"sync"

	"go.uber.org/zap"

	"github.com/razatechofficial/edr/internal/detection/ioc"
)

// GeoIPDB is the interface for any GeoIP lookup provider (MaxMind, etc.).
type GeoIPDB interface {
	LookupCountry(ip string) (country, city string, err error)
	LookupASN(ip string) (asn, org string, err error)
}

// Enricher adds contextual metadata to normalised events: process ancestry,
// geo-IP, ASN information, IOC threat tags, and OS user/group resolution.
type Enricher struct {
	mu      sync.RWMutex
	geoIP   GeoIPDB
	matcher *ioc.Matcher
	logger  *zap.Logger

	processTree sync.Map // pid -> parent info cache
}

type processInfo struct {
	PID         int
	PPID        int
	ProcessName string
}

// NewEnricher creates an Enricher. geoIP and matcher may be nil if those
// enrichment sources are not available.
func NewEnricher(geoIP GeoIPDB, matcher *ioc.Matcher, logger *zap.Logger) *Enricher {
	return &Enricher{
		geoIP:   geoIP,
		matcher: matcher,
		logger:  logger,
	}
}

// Enrich augments a NormalizedEvent with all available contextual data and
// returns the same pointer for chaining convenience.
func (e *Enricher) Enrich(event *NormalizedEvent) *NormalizedEvent {
	e.enrichProcessTree(event)
	e.enrichGeoIP(event)
	e.enrichThreatIntel(event)
	e.enrichUserGroup(event)
	return event
}

// UpdateProcessTree records a process relationship for later parent-chain
// lookups. Callers should invoke this for every process-create event.
func (e *Enricher) UpdateProcessTree(pid, ppid int, name string) {
	e.processTree.Store(pid, processInfo{PID: pid, PPID: ppid, ProcessName: name})
}

func (e *Enricher) enrichProcessTree(event *NormalizedEvent) {
	if event.PID == 0 {
		return
	}

	e.UpdateProcessTree(event.PID, event.PPID, event.ProcessName)

	const maxDepth = 16
	var chain []string
	pid := event.PPID
	for i := 0; i < maxDepth && pid > 1; i++ {
		val, ok := e.processTree.Load(pid)
		if !ok {
			chain = append(chain, fmt.Sprintf("pid:%d", pid))
			break
		}
		info := val.(processInfo)
		chain = append(chain, fmt.Sprintf("%s(%d)", info.ProcessName, info.PID))
		pid = info.PPID
	}
	if len(chain) > 0 {
		event.ParentChain = chain
	}
}

func (e *Enricher) enrichGeoIP(event *NormalizedEvent) {
	if e.geoIP == nil {
		return
	}

	ip := event.DestIP
	if ip == "" {
		ip = event.SourceIP
	}
	if ip == "" {
		return
	}

	parsed := net.ParseIP(ip)
	if parsed == nil || parsed.IsLoopback() || parsed.IsPrivate() || parsed.IsLinkLocalUnicast() {
		return
	}

	if country, city, err := e.geoIP.LookupCountry(ip); err == nil {
		event.GeoCountry = country
		event.GeoCity = city
	} else {
		e.logger.Debug("geo-ip country lookup failed", zap.String("ip", ip), zap.Error(err))
	}

	if asn, org, err := e.geoIP.LookupASN(ip); err == nil {
		event.ASN = asn
		event.ASOrg = org
	} else {
		e.logger.Debug("geo-ip asn lookup failed", zap.String("ip", ip), zap.Error(err))
	}
}

func (e *Enricher) enrichThreatIntel(event *NormalizedEvent) {
	if e.matcher == nil {
		return
	}

	var tags []string

	for _, h := range event.Hashes {
		if r := e.matcher.CheckHash(h); r.Matched {
			tags = append(tags, r.Tags...)
			if r.MalwareFamily != "" {
				tags = append(tags, "malware:"+r.MalwareFamily)
			}
		}
	}
	if event.FileHash != "" {
		if r := e.matcher.CheckHash(event.FileHash); r.Matched {
			tags = append(tags, r.Tags...)
		}
	}
	if event.DestIP != "" {
		if r := e.matcher.CheckIP(event.DestIP); r.Matched {
			tags = append(tags, r.Tags...)
		}
	}
	if event.Domain != "" {
		if r := e.matcher.CheckDomain(event.Domain); r.Matched {
			tags = append(tags, r.Tags...)
		}
	}

	if len(tags) > 0 {
		event.ThreatTags = dedup(tags)
	}
}

func (e *Enricher) enrichUserGroup(event *NormalizedEvent) {
	if event.User == "" {
		return
	}

	if _, err := strconv.Atoi(event.User); err == nil {
		if u, err := user.LookupId(event.User); err == nil {
			event.ResolvedUser = u.Username
		}
	} else {
		event.ResolvedUser = event.User
	}

	if event.ResolvedUser != "" {
		if u, err := user.Lookup(event.ResolvedUser); err == nil {
			event.ResolvedGroup = u.Gid
		}
	}
}

func dedup(items []string) []string {
	seen := make(map[string]struct{}, len(items))
	out := make([]string, 0, len(items))
	for _, s := range items {
		if _, ok := seen[s]; !ok {
			seen[s] = struct{}{}
			out = append(out, s)
		}
	}
	return out
}
