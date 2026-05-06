//go:build windows

package collector

import (
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/razatechofficial/edr/internal/kernel"
	"github.com/razatechofficial/edr/internal/schema"
	"golang.org/x/sys/windows"
)

// pwshDefenderChannel describes one operational event-log channel that the
// agent consumes via EvtSubscribe alongside the Security channel handled by
// AuthCollector. Each channel carries its own bookmark so a problem in one
// (channel disabled, ACL change) does not stall the others.
type pwshDefenderChannel struct {
	name      string
	query     string
	bookmark  string // bookmark filename suffix
	mapEvent  func(endpointID, hostname, xmlText string) *Telemetry
}

var pwshDefenderChannels = []pwshDefenderChannel{
	{
		name:     "Microsoft-Windows-PowerShell/Operational",
		query:    "*[System[(EventID=4103 or EventID=4104)]]",
		bookmark: "powershell_bookmark.xml",
		mapEvent: mapPowerShellEventXML,
	},
	{
		name:     `Microsoft-Windows-Windows Defender/Operational`,
		query:    "*[System[(EventID=1116 or EventID=1117 or EventID=1118 or EventID=1119 or EventID=5001 or EventID=5004 or EventID=5007 or EventID=5010 or EventID=5012)]]",
		bookmark: "defender_bookmark.xml",
		mapEvent: mapDefenderEventXML,
	},
	{
		name:     "Microsoft-Windows-AppLocker/EXE and DLL",
		query:    "*[System[(EventID=8003 or EventID=8004 or EventID=8006 or EventID=8007)]]",
		bookmark: "applocker_bookmark.xml",
		mapEvent: mapAppLockerEventXML,
	},
	{
		name:     "Microsoft-Windows-TaskScheduler/Operational",
		query:    "*[System[(EventID=106 or EventID=200 or EventID=201)]]",
		bookmark: "taskscheduler_bookmark.xml",
		mapEvent: mapGenericOperationalXML("taskscheduler"),
	},
	{
		name:     "Microsoft-Windows-WMI-Activity/Operational",
		query:    "*",
		bookmark: "wmi_activity_bookmark.xml",
		mapEvent: mapGenericOperationalXML("wmi_activity"),
	},
	{
		name:     "Microsoft-Windows-BITS-Client/Operational",
		query:    "*",
		bookmark: "bits_client_bookmark.xml",
		mapEvent: mapGenericOperationalXML("bits_client"),
	},
	{
		name:     "Microsoft-Windows-Windows Firewall With Advanced Security/Firewall",
		query:    "*",
		bookmark: "firewall_bookmark.xml",
		mapEvent: mapGenericOperationalXML("firewall"),
	},
	{
		name:     "System",
		query:    "*[System[EventID=7045]]",
		bookmark: "system_svc_install_bookmark.xml",
		mapEvent: mapGenericOperationalXML("system_service_install"),
	},
}

// PowerShellDefenderSource consumes script logging, Defender, and AppLocker
// channels in parallel. Each channel is independent: a single channel that is
// disabled or unavailable does not affect the others.
type PowerShellDefenderSource struct {
	endpointID string
	hostname   string
	dataDir    string

	mu     sync.Mutex // guards: states
	states []*pwshChannelState

	emitted atomic.Uint64
	dropped atomic.Uint64
	errs    atomic.Pointer[string]
}

type pwshChannelState struct {
	cfg      pwshDefenderChannel
	bmPath   string
	bookmark windows.Handle
	result   windows.Handle
	primed   bool
	useSub   bool
	seen     uint64
}

// NewPowerShellDefenderSource constructs the multi-channel event log source.
func NewPowerShellDefenderSource(endpointID, hostname, dataDir string) *PowerShellDefenderSource {
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
	return &PowerShellDefenderSource{
		endpointID: endpointID,
		hostname:   hostname,
		dataDir:    dataDir,
	}
}

// Snapshot drains queued events from each subscribed channel.
func (s *PowerShellDefenderSource) Snapshot(ctx context.Context) ([]Telemetry, error) {
	s.mu.Lock()
	if len(s.states) == 0 {
		if err := s.initLocked(); err != nil {
			s.mu.Unlock()
			s.recordError(err)
			return nil, err
		}
	}
	states := append([]*pwshChannelState(nil), s.states...)
	s.mu.Unlock()

	var out []Telemetry
	handles := make([]windows.Handle, 64)
	for _, st := range states {
		if st.result == 0 {
			continue
		}
		timeout := uint32(0)
		if !st.useSub {
			timeout = 1500
		}
		for {
			if ctx.Err() != nil {
				return out, ctx.Err()
			}
			n, err := kernel.EvtNext(st.result, handles, timeout, 0)
			if err != nil {
				if errno, ok := err.(windows.Errno); ok &&
					(errno == windows.ERROR_NO_MORE_ITEMS || errno == windows.ERROR_TIMEOUT) {
					break
				}
				s.recordError(err)
				break
			}
			if n == 0 {
				break
			}
			for i := uint32(0); i < n; i++ {
				h := handles[i]
				tel := s.renderAndMap(st, h)
				_ = kernel.EvtUpdateBookmark(st.bookmark, h)
				kernel.EvtClose(h)
				if tel == nil {
					s.dropped.Add(1)
					continue
				}
				if !st.primed {
					continue
				}
				out = append(out, *tel)
				s.emitted.Add(1)
				st.seen++
				if st.seen%100 == 0 {
					_ = st.saveBookmarkAtomic()
				}
			}
			if !st.useSub {
				break
			}
		}
		if !st.primed {
			st.primed = true
			_ = st.saveBookmarkAtomic()
		}
	}
	return out, nil
}

func (s *PowerShellDefenderSource) Name() string { return "powershell_defender" }

// Collect implements Collector by draining PowerShell/Defender/AppLocker queues.
func (s *PowerShellDefenderSource) Collect(ctx context.Context) ([]Telemetry, error) {
	return s.Snapshot(ctx)
}

// Close releases all subscription/bookmark handles.
func (s *PowerShellDefenderSource) Close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, st := range s.states {
		kernel.EvtClose(st.result)
		kernel.EvtClose(st.bookmark)
		st.result = 0
		st.bookmark = 0
	}
}

// ExportMonitoringHealth surfaces per-collector status to the doctor command.
func (s *PowerShellDefenderSource) ExportMonitoringHealth() map[string]any {
	src := MonitoringSource{
		Name:    "powershell_defender",
		OS:      "windows",
		Source:  "evtsubscribe",
		Status:  "healthy",
		EPSOut:  s.emitted.Load(),
		Dropped: s.dropped.Load(),
	}
	s.mu.Lock()
	active := 0
	for _, st := range s.states {
		if st.result != 0 {
			active++
		}
	}
	total := len(s.states)
	s.mu.Unlock()
	switch {
	case total == 0:
		src.Status = "unavailable"
	case active == 0:
		src.Status = "degraded"
	case active < total:
		src.Status = "degraded"
		src.Notes = "some channels unavailable"
	}
	if errPtr := s.errs.Load(); errPtr != nil && *errPtr != "" {
		src.LastError = *errPtr
	}
	return src.ToMap()
}

func (s *PowerShellDefenderSource) initLocked() error {
	if err := os.MkdirAll(s.dataDir, 0o700); err != nil {
		return err
	}
	for _, cfg := range pwshDefenderChannels {
		st, err := s.openChannel(cfg)
		if err != nil {
			s.recordError(err)
			continue
		}
		s.states = append(s.states, st)
	}
	if len(s.states) == 0 {
		return errors.New("no PowerShell/Defender channels available")
	}
	return nil
}

func (s *PowerShellDefenderSource) openChannel(cfg pwshDefenderChannel) (*pwshChannelState, error) {
	st := &pwshChannelState{cfg: cfg}
	bookmarkPath := filepath.Join(s.dataDir, cfg.bookmark)
	st.bmPath = bookmarkPath
	if _, err := readBookmarkFile(bookmarkPath); err == nil {
		pathU16, _ := windows.UTF16PtrFromString(bookmarkPath)
		if h, err := kernel.EvtLoadBookmark(pathU16); err == nil {
			st.bookmark = h
			st.primed = true
		}
	}
	if st.bookmark == 0 {
		h, err := kernel.EvtCreateBookmark(nil)
		if err != nil {
			return nil, err
		}
		st.bookmark = h
	}
	ch, _ := windows.UTF16PtrFromString(cfg.name)
	q, _ := windows.UTF16PtrFromString(cfg.query)
	if sub, err := kernel.EvtSubscribe(0, 0, ch, q, st.bookmark, 0, 0,
		kernel.EvtSubscribeToFutureEvents); err == nil {
		st.result = sub
		st.useSub = true
		return st, nil
	}
	rs, err := kernel.EvtQuery(nil, ch, q, kernel.EvtQueryChannelPath)
	if err != nil {
		kernel.EvtClose(st.bookmark)
		return nil, err
	}
	st.result = rs
	st.useSub = false
	return st, nil
}

func (s *pwshChannelState) saveBookmarkAtomic() error {
	if s == nil || s.bookmark == 0 || s.bmPath == "" {
		return nil
	}
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

func (s *PowerShellDefenderSource) renderAndMap(st *pwshChannelState, h windows.Handle) *Telemetry {
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
	return st.cfg.mapEvent(s.endpointID, s.hostname, windows.UTF16ToString(buf))
}

func (s *PowerShellDefenderSource) recordError(err error) {
	if err == nil {
		return
	}
	msg := err.Error()
	s.errs.Store(&msg)
}

// mapPowerShellEventXML maps PowerShell Operational 4103/4104 to ProcessEvent.
// 4104 is the high-fidelity event (script block logging); 4103 is module
// pipeline execution and is treated as a noisy companion.
func mapPowerShellEventXML(endpointID, hostname, xmlText string) *Telemetry {
	var ev winEventXML
	if err := xml.Unmarshal([]byte(xmlText), &ev); err != nil {
		return nil
	}
	fields := evtFields(ev)
	base := evtBase(endpointID, hostname, ev)
	base.EventType = schema.EventProcess
	pe := &schema.ProcessEvent{
		BaseEvent:   base,
		PID:         atoiSafe(fields["ProcessId"]),
		ProcessName: "powershell",
		ProcessPath: fields["Path"],
		User:        fields["UserId"],
		CommandLine: firstNonEmpty(fields["ScriptBlockText"], fields["Payload"]),
		Tags:        []string{"powershell"},
	}
	if ev.System.EventID == 4104 {
		pe.Tags = append(pe.Tags, "script_block")
		pe.Severity = "medium"
	}
	return &Telemetry{Process: pe}
}

// mapDefenderEventXML maps Defender Operational malware/protection events.
func mapDefenderEventXML(endpointID, hostname, xmlText string) *Telemetry {
	var ev winEventXML
	if err := xml.Unmarshal([]byte(xmlText), &ev); err != nil {
		return nil
	}
	fields := evtFields(ev)
	base := evtBase(endpointID, hostname, ev)
	base.EventType = schema.EventProcess
	tags := []string{"defender"}
	severity := "medium"
	switch ev.System.EventID {
	case 1116, 1117, 1118, 1119:
		tags = append(tags, "malware")
		severity = "high"
	case 5001, 5004, 5007, 5010, 5012:
		tags = append(tags, "config_change")
	}
	pe := &schema.ProcessEvent{
		BaseEvent:   base,
		ProcessName: "defender",
		ProcessPath: firstNonEmpty(fields["Path"], fields["Process Name"]),
		CommandLine: firstNonEmpty(fields["Threat Name"], fields["Action Name"], fields["Detection User"]),
		Tags:        tags,
		Severity:    severity,
	}
	return &Telemetry{Process: pe}
}

// mapAppLockerEventXML maps AppLocker EXE/DLL channel events.
// mapGenericOperationalXML maps additional bookmarked operational channels (G-BLS-MATRIX).
func mapGenericOperationalXML(kind string) func(endpointID, hostname, xmlText string) *Telemetry {
	return func(endpointID, hostname, xmlText string) *Telemetry {
		var ev winEventXML
		if err := xml.Unmarshal([]byte(xmlText), &ev); err != nil {
			return nil
		}
		fields := evtFields(ev)
		base := evtBase(endpointID, hostname, ev)
		base.EventType = schema.EventProcess
		pe := &schema.ProcessEvent{
			BaseEvent:   base,
			ProcessName: kind,
			CommandLine: firstNonEmpty(
				fmt.Sprintf("eid=%d", ev.System.EventID),
				fields["TaskName"], fields["SubjectUserName"], fields["ServiceName"], fields["ClientMachine"]),
			Tags: []string{kind, "evtx_operational"},
		}
		return &Telemetry{Process: pe}
	}
}

func mapAppLockerEventXML(endpointID, hostname, xmlText string) *Telemetry {
	var ev winEventXML
	if err := xml.Unmarshal([]byte(xmlText), &ev); err != nil {
		return nil
	}
	fields := evtFields(ev)
	base := evtBase(endpointID, hostname, ev)
	base.EventType = schema.EventProcess
	tag := "applocker_blocked"
	if ev.System.EventID == 8003 || ev.System.EventID == 8006 {
		tag = "applocker_audit"
	}
	pe := &schema.ProcessEvent{
		BaseEvent:   base,
		ProcessName: "applocker",
		ProcessPath: firstNonEmpty(fields["TargetUser"], fields["FullFilePath"]),
		CommandLine: fields["FullFilePath"],
		PID:         atoiSafe(fields["TargetProcessId"]),
		Tags:        []string{tag},
	}
	return &Telemetry{Process: pe}
}

func evtFields(ev winEventXML) map[string]string {
	out := make(map[string]string, len(ev.EventData.Data))
	for _, d := range ev.EventData.Data {
		out[d.Name] = strings.TrimSpace(d.Value)
	}
	return out
}

func evtBase(endpointID, hostname string, ev winEventXML) schema.BaseEvent {
	ts := time.Now().UTC()
	if t, err := time.Parse(time.RFC3339Nano, strings.TrimSpace(ev.System.TimeCreated.SystemTime)); err == nil {
		ts = t.UTC()
	}
	return schema.BaseEvent{
		SchemaVersion: schema.SchemaVersionV1,
		EndpointID:    endpointID,
		Timestamp:     ts,
		Hostname:      hostname,
		OS:            "windows",
	}
}
