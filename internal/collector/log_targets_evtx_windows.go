//go:build windows

package collector

import (
	"context"
	"encoding/xml"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/razatechofficial/edr/internal/kernel"
	"github.com/razatechofficial/edr/internal/schema"
	"golang.org/x/sys/windows"
)

type evtxLogTargetState struct {
	mu           sync.Mutex
	channel      string
	query        string
	bookmarkPath string
	result       windows.Handle
	bookmark     windows.Handle
	useSubscribe bool
	primed       bool
	seenEvents   uint64
}

func (l *LogTargetsCollector) initTargetPlatform(st *logTargetRuntime) {
	if strings.ToLower(strings.TrimSpace(st.target.Type)) != "eventchannel" {
		return
	}
	dd := strings.TrimSpace(l.cfg.Agent.DataDir)
	if dd == "" {
		dd = "."
	}
	ch := strings.TrimSpace(st.target.Path)
	q := strings.TrimSpace(st.target.Query)
	if q == "" {
		q = "*"
	}
	bm := filepath.Join(dd, fmt.Sprintf("log_target_%d_bookmark.xml", st.idx))
	st.evtx = &evtxLogTargetState{
		channel:      ch,
		query:        q,
		bookmarkPath: bm,
	}
}

func (l *LogTargetsCollector) collectWindowsEventChannel(ctx context.Context, st *logTargetRuntime) ([]Telemetry, error) {
	_ = ctx
	s, ok := st.evtx.(*evtxLogTargetState)
	if !ok || s == nil {
		return nil, fmt.Errorf("evtx state missing")
	}
	return s.collect(l.endpointID, l.hostname, st.target.Path)
}

func (s *evtxLogTargetState) closeAll() {
	if s == nil {
		return
	}
	kernel.EvtClose(s.result)
	kernel.EvtClose(s.bookmark)
	s.result = 0
	s.bookmark = 0
}

func (s *evtxLogTargetState) init() error {
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
	ch, _ := windows.UTF16PtrFromString(s.channel)
	q, _ := windows.UTF16PtrFromString(s.query)
	if sub, err := kernel.EvtSubscribe(0, 0, ch, q, s.bookmark, 0, 0, kernel.EvtSubscribeToFutureEvents); err == nil {
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

func (s *evtxLogTargetState) saveBookmarkAtomic() error {
	tmp := s.bookmarkPath + ".tmp"
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
	return writeBookmarkFile(s.bookmarkPath, b)
}

func (s *evtxLogTargetState) collect(endpointID, hostname, channel string) ([]Telemetry, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.result == 0 {
		if err := s.init(); err != nil {
			s.closeAll()
			return nil, err
		}
	}
	handles := make([]windows.Handle, 64)
	timeout := uint32(0)
	if !s.useSubscribe {
		timeout = 1500
	}
	var out []Telemetry
	for {
		n, err := kernel.EvtNext(s.result, handles, timeout, 0)
		if err != nil {
			if errno, ok := err.(windows.Errno); ok && (errno == windows.ERROR_NO_MORE_ITEMS || errno == windows.ERROR_TIMEOUT) {
				break
			}
			return out, err
		}
		if n == 0 {
			break
		}
		for i := uint32(0); i < n; i++ {
			h := handles[i]
			xmlText, rerr := renderEvtXML(h)
			_ = kernel.EvtUpdateBookmark(s.bookmark, h)
			kernel.EvtClose(h)
			if rerr != nil || xmlText == "" {
				continue
			}
			if !s.primed {
				continue
			}
			if tel := mapLogTargetEventXML(endpointID, hostname, channel, xmlText); tel != nil {
				out = append(out, *tel)
			} else {
				ts := time.Now().UTC()
				ev := schema.FileEvent{
					BaseEvent: schema.BaseEvent{
						SchemaVersion: schema.SchemaVersionV1,
						EventType:     schema.EventFile,
						EndpointID:    endpointID,
						Timestamp:     ts,
						Hostname:      hostname,
						OS:            "windows",
					},
					Path:         channel,
					Operation:    "log_evtx_xml",
					ActorPID:     0,
					BytesWritten: uint64(len(xmlText)),
				}
				out = append(out, Telemetry{File: &ev})
			}
			s.seenEvents++
			if s.seenEvents%50 == 0 {
				_ = s.saveBookmarkAtomic()
			}
		}
		if !s.useSubscribe {
			break
		}
	}
	if !s.primed {
		s.primed = true
		_ = s.saveBookmarkAtomic()
	}
	return out, nil
}

func mapLogTargetEventXML(endpointID, hostname, channel, xmlText string) *Telemetry {
	var ev winEventXML
	if err := xml.Unmarshal([]byte(xmlText), &ev); err != nil {
		return nil
	}
	fields := evtFields(ev)
	base := evtBase(endpointID, hostname, ev)
	base.EventType = schema.EventProcess
	pe := &schema.ProcessEvent{
		BaseEvent:   base,
		PID:         atoiSafe(firstNonEmpty(fields["ProcessId"], fields["Execution ProcessID"])),
		ProcessName: "log_target_eventchannel",
		ProcessPath: channel,
		CommandLine: firstNonEmpty(fields["TaskName"], fields["ServiceName"], fields["CommandLine"], "event_id="+strconv.FormatUint(uint64(ev.System.EventID), 10)),
		Tags:        []string{"log_target", "eventchannel", strings.ToLower(strings.ReplaceAll(channel, " ", "_"))},
	}
	return &Telemetry{Process: pe}
}

func renderEvtXML(h windows.Handle) (string, error) {
	buf := make([]uint16, 8192)
	used, _, err := kernel.EvtRender(0, h, kernel.EvtRenderEventXML, buf)
	if err != nil {
		if errno, ok := err.(windows.Errno); !ok || errno != windows.ERROR_INSUFFICIENT_BUFFER {
			return "", err
		}
		nChars := int((used + 1) / 2)
		buf = make([]uint16, nChars)
		if _, _, err = kernel.EvtRender(0, h, kernel.EvtRenderEventXML, buf); err != nil {
			return "", err
		}
	}
	return windows.UTF16ToString(buf), nil
}
