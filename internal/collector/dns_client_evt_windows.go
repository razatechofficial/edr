//go:build windows

package collector

import (
	"context"
	"html"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/razatechofficial/edr/internal/kernel"
	"github.com/razatechofficial/edr/internal/schema"
	"golang.org/x/sys/windows"
)

const (
	dnsEvtChannel = "Microsoft-Windows-DNS Client/Operational"
	dnsEvtQuery   = "*[System[Provider[@Name='Microsoft-Windows-DNS-Client']]]"
)

// DnsClientEVTSource streams DNS Client operational channel into NetworkEvent (protocol=dns).
type DnsClientEVTSource struct {
	endpointID string
	hostname   string
	dataDir    string

	mu        sync.Mutex
	result    windows.Handle
	bookmark  windows.Handle
	bmPath    string
	subscribe bool
	primed    bool

	emitted atomic.Uint64
	errs    atomic.Pointer[string]
}

func NewDnsClientEVTSource(endpointID, dataDir string) *DnsClientEVTSource {
	host, _ := os.Hostname()
	if dataDir == "" {
		dataDir = "."
	}
	return &DnsClientEVTSource{
		endpointID: endpointID,
		hostname:   host,
		dataDir:    dataDir,
		bmPath:     filepath.Join(dataDir, "dns_client_bookmark.xml"),
	}
}

func (s *DnsClientEVTSource) recordError(err error) {
	if err == nil {
		return
	}
	msg := err.Error()
	s.errs.Store(&msg)
}

func (s *DnsClientEVTSource) init() error {
	if err := os.MkdirAll(filepath.Dir(s.bmPath), 0o700); err != nil {
		return err
	}
	if _, err := readBookmarkFile(s.bmPath); err == nil {
		pathU16, _ := windows.UTF16PtrFromString(s.bmPath)
		if h, err := kernel.EvtLoadBookmark(pathU16); err == nil {
			s.bookmark = h
			s.primed = true
		}
	}
	if s.bookmark == 0 {
		h, err := kernel.EvtCreateBookmark(nil)
		if err != nil {
			return err
		}
		s.bookmark = h
		s.primed = false
	}
	ch, _ := windows.UTF16PtrFromString(dnsEvtChannel)
	q, _ := windows.UTF16PtrFromString(dnsEvtQuery)
	if sub, err := kernel.EvtSubscribe(0, 0, ch, q, s.bookmark, 0, 0, kernel.EvtSubscribeToFutureEvents); err == nil {
		s.result = sub
		s.subscribe = true
		return nil
	}
	rs, err := kernel.EvtQuery(nil, ch, q, kernel.EvtQueryChannelPath)
	if err != nil {
		return err
	}
	s.result = rs
	s.subscribe = false
	return nil
}

func (s *DnsClientEVTSource) saveBookmarkAtomic() error {
	tmp := s.bmPath + ".tmp"
	tmpU16, err := windows.UTF16PtrFromString(tmp)
	if err != nil {
		return err
	}
	if err := kernel.EvtSaveBookmark(s.bookmark, tmpU16); err != nil {
		return err
	}
	b, err := os.ReadFile(tmp)
	if err != nil {
		return err
	}
	return writeBookmarkFile(s.bmPath, b)
}

// Run drains EventLog until ctx done.
func (s *DnsClientEVTSource) Run(ctx context.Context, sink *StreamingSink) error {
	s.mu.Lock()
	if s.result == 0 {
		if err := s.init(); err != nil {
			s.mu.Unlock()
			s.recordError(err)
			return err
		}
	}
	s.mu.Unlock()

	handles := make([]windows.Handle, 128)
	seen := uint64(0)
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		timeout := uint32(0)
		if !s.subscribe {
			timeout = 1500
		}
		n, err := kernel.EvtNext(s.result, handles, timeout, 0)
		if err != nil {
			if errno, ok := err.(windows.Errno); ok && (errno == windows.ERROR_NO_MORE_ITEMS || errno == windows.ERROR_TIMEOUT) {
				if !s.subscribe {
					time.Sleep(400 * time.Millisecond)
				}
				continue
			}
			s.recordError(err)
			time.Sleep(time.Second)
			continue
		}
		if n == 0 {
			continue
		}
		for i := uint32(0); i < n; i++ {
			h := handles[i]
			tel := s.mapEvent(h)
			_ = kernel.EvtUpdateBookmark(s.bookmark, h)
			kernel.EvtClose(h)
			if tel == nil || !s.primed {
				continue
			}
			if sink.Send(ctx, *tel) {
				s.emitted.Add(1)
				seen++
				if seen%50 == 0 {
					_ = s.saveBookmarkAtomic()
				}
			}
		}
		if !s.subscribe {
			time.Sleep(300 * time.Millisecond)
		}
		if !s.primed {
			s.primed = true
			_ = s.saveBookmarkAtomic()
		}
	}
}

var dnsQueryNameRe = regexp.MustCompile(`(?i)<Data[^>]*Name="QueryName"[^>]*>([^<]+)</Data>`)

func (s *DnsClientEVTSource) mapEvent(h windows.Handle) *Telemetry {
	buf := make([]uint16, 8192)
	used, _, err := kernel.EvtRender(0, h, kernel.EvtRenderEventXML, buf)
	if err != nil {
		if errno, ok := err.(windows.Errno); !ok || errno != windows.ERROR_INSUFFICIENT_BUFFER {
			return nil
		}
		nChars := int((used + 1) / 2)
		buf = make([]uint16, nChars)
		if _, _, err = kernel.EvtRender(0, h, kernel.EvtRenderEventXML, buf); err != nil {
			return nil
		}
	}
	xmlText := windows.UTF16ToString(buf)
	q := extractDNSQuery(xmlText)
	if q == "" {
		return nil
	}
	now := time.Now().UTC()
	ne := &schema.NetworkEvent{
		BaseEvent: schema.BaseEvent{
			SchemaVersion: schema.SchemaVersionV1,
			EventType:     schema.EventNetwork,
			EndpointID:    s.endpointID,
			Timestamp:     now,
			Hostname:      s.hostname,
			OS:            "windows",
		},
		PID:      0,
		Protocol: "dns",
		Domain:   strings.TrimSpace(q),
	}
	return &Telemetry{Network: ne}
}

func extractDNSQuery(xmlText string) string {
	if m := dnsQueryNameRe.FindStringSubmatch(xmlText); len(m) > 1 {
		return strings.TrimSpace(html.UnescapeString(strings.TrimSpace(m[1])))
	}
	return ""
}

// ExportMonitoringHealth implements streaming source health.
func (s *DnsClientEVTSource) ExportMonitoringHealth() map[string]any {
	src := MonitoringSource{
		Name:   "dns_client",
		OS:     "windows",
		Source: "evtsubscribe_dns",
		Status: "healthy",
		EPSOut: s.emitted.Load(),
	}
	s.mu.Lock()
	active := s.result != 0
	s.mu.Unlock()
	if !active && s.errs.Load() == nil {
		src.Status = "unavailable"
	}
	if errPtr := s.errs.Load(); errPtr != nil && *errPtr != "" {
		src.LastError = *errPtr
		src.Status = "degraded"
	}
	return src.ToMap()
}
