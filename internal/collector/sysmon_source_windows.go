//go:build windows

package collector

import (
	"context"
	"encoding/xml"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/razatechofficial/edr/internal/kernel"
	"github.com/razatechofficial/edr/internal/schema"
	"golang.org/x/sys/windows"
)

const (
	sysmonChannel = "Microsoft-Windows-Sysmon/Operational"
	// Subscribe to the high-value Sysmon events. Operators can extend this
	// query via configuration in a follow-up commit.
	sysmonQuery = "*[System[(EventID=1 or EventID=3 or EventID=5 or EventID=7 or EventID=8 or EventID=10 or EventID=11 or EventID=12 or EventID=13 or EventID=14 or EventID=22 or EventID=25)]]"
)

// SysmonSource consumes the Microsoft-Windows-Sysmon/Operational channel via
// EvtSubscribe and maps the most useful Sysmon events into schema telemetry.
//
// It only activates when the SysmonDetector reports the channel is present;
// otherwise Snapshot returns immediately so the agent does not log spurious
// "channel not found" errors on Sysmon-less hosts.
type SysmonSource struct {
	endpointID string
	hostname   string
	dataDir    string

	mu            sync.Mutex // guards: result, bookmark, primed
	result        windows.Handle
	bookmark      windows.Handle
	bookmarkPath  string
	useSubscribe  bool
	primed        bool
	channelExists bool

	emitted atomic.Uint64
	dropped atomic.Uint64
	errs    atomic.Pointer[string]
}

// NewSysmonSource constructs a Sysmon channel consumer. dataDir is used to
// persist the EvtSubscribe bookmark so restarts do not replay or skip events.
func NewSysmonSource(endpointID, hostname, dataDir string) *SysmonSource {
	if hostname == "" {
		if h, err := os.Hostname(); err == nil {
			hostname = h
		} else {
			hostname = "unknown"
		}
	}
	if dataDir == "" {
		dataDir = "."
	}
	return &SysmonSource{
		endpointID:   endpointID,
		hostname:     hostname,
		dataDir:      dataDir,
		bookmarkPath: filepath.Join(dataDir, "sysmon_bookmark.xml"),
	}
}

// SetChannelPresent marks whether the Sysmon channel exists. Pass the value
// from SysmonDetector.Probe().ChannelPresent so we skip subscribe attempts on
// hosts that lack Sysmon.
func (s *SysmonSource) SetChannelPresent(present bool) {
	s.mu.Lock()
	s.channelExists = present
	s.mu.Unlock()
}

// Snapshot drains queued Sysmon events into Telemetry. Returns nil when the
// channel is absent so the caller can treat that as steady-state.
func (s *SysmonSource) Snapshot(ctx context.Context) ([]Telemetry, error) {
	s.mu.Lock()
	if !s.channelExists {
		s.mu.Unlock()
		return nil, nil
	}
	if s.result == 0 {
		if err := s.init(); err != nil {
			s.mu.Unlock()
			s.recordError(err)
			return nil, err
		}
	}
	s.mu.Unlock()

	handles := make([]windows.Handle, 64)
	timeout := uint32(0)
	if !s.useSubscribe {
		timeout = 1500
	}
	var out []Telemetry
	for {
		if ctx.Err() != nil {
			return out, ctx.Err()
		}
		n, err := kernel.EvtNext(s.result, handles, timeout, 0)
		if err != nil {
			if errno, ok := err.(windows.Errno); ok &&
				(errno == windows.ERROR_NO_MORE_ITEMS || errno == windows.ERROR_TIMEOUT) {
				break
			}
			s.recordError(err)
			return out, err
		}
		if n == 0 {
			break
		}
		for i := uint32(0); i < n; i++ {
			h := handles[i]
			tel := s.renderAndMap(h)
			_ = kernel.EvtUpdateBookmark(s.bookmark, h)
			kernel.EvtClose(h)
			if tel == nil {
				s.dropped.Add(1)
				continue
			}
			if !s.primed {
				continue
			}
			out = append(out, *tel)
			s.emitted.Add(1)
		}
		if !s.useSubscribe {
			break
		}
	}
	if !s.primed {
		s.primed = true
	}
	return out, nil
}

func (s *SysmonSource) Name() string { return "sysmon_evt" }

// Collect implements Collector by draining queued Sysmon events.
func (s *SysmonSource) Collect(ctx context.Context) ([]Telemetry, error) {
	return s.Snapshot(ctx)
}

// Close releases the bookmark + subscription handles.
func (s *SysmonSource) Close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	kernel.EvtClose(s.result)
	kernel.EvtClose(s.bookmark)
	s.result = 0
	s.bookmark = 0
}

// ExportMonitoringHealth surfaces consumption stats for the doctor command.
func (s *SysmonSource) ExportMonitoringHealth() map[string]any {
	src := MonitoringSource{
		Name:    "sysmon_evt",
		OS:      "windows",
		Source:  "evtsubscribe",
		Status:  "unavailable",
		EPSOut:  s.emitted.Load(),
		Dropped: s.dropped.Load(),
	}
	s.mu.Lock()
	if s.channelExists {
		if s.result != 0 {
			src.Status = "healthy"
		} else {
			src.Status = "degraded"
		}
	}
	s.mu.Unlock()
	if errPtr := s.errs.Load(); errPtr != nil && *errPtr != "" {
		src.LastError = *errPtr
		src.Status = "degraded"
	}
	return src.ToMap()
}

func (s *SysmonSource) init() error {
	if err := os.MkdirAll(filepath.Dir(s.bookmarkPath), 0o700); err != nil {
		return err
	}
	if _, err := readBookmarkFile(s.bookmarkPath); err == nil {
		pathU16, _ := windows.UTF16PtrFromString(s.bookmarkPath)
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
	ch, _ := windows.UTF16PtrFromString(sysmonChannel)
	q, _ := windows.UTF16PtrFromString(sysmonQuery)
	if sub, err := kernel.EvtSubscribe(0, 0, ch, q, s.bookmark, 0, 0,
		kernel.EvtSubscribeToFutureEvents); err == nil {
		s.result = sub
		s.useSubscribe = true
		return nil
	}
	rs, err := kernel.EvtQuery(nil, ch, q, kernel.EvtQueryChannelPath)
	if err != nil {
		return err
	}
	s.result = rs
	s.useSubscribe = false
	return nil
}

func (s *SysmonSource) renderAndMap(h windows.Handle) *Telemetry {
	buf := make([]uint16, 8192)
	used, _, err := kernel.EvtRender(0, h, kernel.EvtRenderEventXML, buf)
	if err != nil {
		errno, ok := err.(windows.Errno)
		if !ok || errno != windows.ERROR_INSUFFICIENT_BUFFER {
			return nil
		}
		nChars := int((used + 1) / 2)
		buf = make([]uint16, nChars)
		if _, _, err = kernel.EvtRender(0, h, kernel.EvtRenderEventXML, buf); err != nil {
			return nil
		}
	}
	return s.mapSysmonXML(windows.UTF16ToString(buf))
}

func (s *SysmonSource) mapSysmonXML(xmlText string) *Telemetry {
	var ev winEventXML
	if err := xml.Unmarshal([]byte(xmlText), &ev); err != nil {
		return nil
	}
	fields := map[string]string{}
	for _, d := range ev.EventData.Data {
		fields[d.Name] = strings.TrimSpace(d.Value)
	}
	ts := time.Now().UTC()
	if t, err := time.Parse(time.RFC3339Nano, strings.TrimSpace(ev.System.TimeCreated.SystemTime)); err == nil {
		ts = t.UTC()
	}
	base := schema.BaseEvent{
		SchemaVersion: schema.SchemaVersionV1,
		EndpointID:    s.endpointID,
		Timestamp:     ts,
		Hostname:      s.hostname,
		OS:            "windows",
	}

	switch ev.System.EventID {
	case 1: // Process Create
		base.EventType = schema.EventProcess
		pe := &schema.ProcessEvent{
			BaseEvent:   base,
			PID:         atoiSafe(fields["ProcessId"]),
			PPID:        atoiSafe(fields["ParentProcessId"]),
			ProcessName: filepath.Base(fields["Image"]),
			ProcessPath: fields["Image"],
			CommandLine: fields["CommandLine"],
			User:        fields["User"],
			ParentName:  filepath.Base(fields["ParentImage"]),
			ImageSHA256: extractSysmonHash(fields["Hashes"], "SHA256"),
			Tags:        []string{"sysmon"},
		}
		return &Telemetry{Process: pe}
	case 5: // Process Terminated
		base.EventType = schema.EventProcess
		return &Telemetry{Process: &schema.ProcessEvent{
			BaseEvent:   base,
			PID:         atoiSafe(fields["ProcessId"]),
			ProcessName: filepath.Base(fields["Image"]),
			ProcessPath: fields["Image"],
			Tags:        []string{"sysmon", "exit"},
		}}
	case 7: // Image Loaded
		base.EventType = schema.EventProcess
		return &Telemetry{Process: &schema.ProcessEvent{
			BaseEvent:   base,
			PID:         atoiSafe(fields["ProcessId"]),
			ProcessName: "image_load",
			ProcessPath: fields["ImageLoaded"],
			ImageSHA256: extractSysmonHash(fields["Hashes"], "SHA256"),
			Tags:        []string{"sysmon", "image_load"},
		}}
	case 8: // CreateRemoteThread
		base.EventType = schema.EventInjection
		return &Telemetry{Injection: &schema.ProcessInjectionEvent{
			BaseEvent:   base,
			SourcePID:   atoiSafe(fields["SourceProcessId"]),
			TargetPID:   atoiSafe(fields["TargetProcessId"]),
			TargetImage: fields["TargetImage"],
			Technique:   "create_remote_thread",
		}}
	case 10: // ProcessAccess
		base.EventType = schema.EventInjection
		return &Telemetry{Injection: &schema.ProcessInjectionEvent{
			BaseEvent:   base,
			SourcePID:   atoiSafe(fields["SourceProcessId"]),
			TargetPID:   atoiSafe(fields["TargetProcessId"]),
			TargetImage: fields["TargetImage"],
			Technique:   "process_access:" + fields["GrantedAccess"],
		}}
	case 11: // FileCreate
		base.EventType = schema.EventFile
		return &Telemetry{File: &schema.FileEvent{
			BaseEvent: base,
			Path:      fields["TargetFilename"],
			Operation: "create",
			ActorPID:  atoiSafe(fields["ProcessId"]),
		}}
	case 12, 13, 14: // Registry: object create/delete, value set, key/value rename
		base.EventType = schema.EventRegistry
		op := "modify"
		if ev.System.EventID == 12 {
			op = "create_or_delete"
		} else if ev.System.EventID == 14 {
			op = "rename"
		}
		return &Telemetry{Registry: &schema.RegistryEvent{
			BaseEvent: base,
			KeyPath:   fields["TargetObject"],
			ValueName: fields["Details"],
			Operation: op,
			ActorPID:  atoiSafe(fields["ProcessId"]),
		}}
	case 3: // Network connection
		base.EventType = schema.EventNetwork
		ne := &schema.NetworkEvent{
			BaseEvent: base,
			PID:       atoiSafe(fields["ProcessId"]),
			Protocol:  strings.ToLower(strings.TrimSpace(firstNonEmpty(fields["Protocol"], "tcp"))),
			SourceIP:  fields["SourceIp"],
			DestIP:    fields["DestinationIp"],
			SourcePt:  atoiSafe(fields["SourcePort"]),
			DestPt:    atoiSafe(fields["DestinationPort"]),
		}
		return &Telemetry{Network: ne}
	case 22: // DNSEvent
		base.EventType = schema.EventNetwork
		return &Telemetry{Network: &schema.NetworkEvent{
			BaseEvent: base,
			PID:       atoiSafe(fields["ProcessId"]),
			Protocol:  "dns",
			Domain:    fields["QueryName"],
		}}
	case 25: // ProcessTampering
		base.EventType = schema.EventProcess
		return &Telemetry{Process: &schema.ProcessEvent{
			BaseEvent:   base,
			PID:         atoiSafe(fields["ProcessId"]),
			ProcessName: "process_tampering",
			ProcessPath: fields["Image"],
			CommandLine: fields["Type"],
			Tags:        []string{"sysmon", "tamper"},
			Severity:    "high",
		}}
	default:
		return nil
	}
}

func (s *SysmonSource) recordError(err error) {
	if err == nil {
		return
	}
	msg := err.Error()
	s.errs.Store(&msg)
}

// extractSysmonHash pulls a single algorithm value from the Sysmon Hashes
// field, which has the form "MD5=...,SHA256=...,IMPHASH=...".
func extractSysmonHash(raw, algo string) string {
	if raw == "" {
		return ""
	}
	for _, part := range strings.Split(raw, ",") {
		kv := strings.SplitN(strings.TrimSpace(part), "=", 2)
		if len(kv) != 2 {
			continue
		}
		if strings.EqualFold(kv[0], algo) {
			return kv[1]
		}
	}
	return ""
}

func atoiSafe(s string) int {
	n, err := strconv.Atoi(strings.TrimSpace(s))
	if err != nil {
		return 0
	}
	return n
}
