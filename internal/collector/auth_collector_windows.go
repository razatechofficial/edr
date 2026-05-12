//go:build windows

package collector

import (
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

const (
	winAuthChannel = "Security"
	// P1-14: broaden the Security-log XPath to cover the canonical
	// event IDs an EDR is expected to ingest. Adding 4634/4647 closes
	// the auth-session loop (logon -> logoff). 4688 surfaces real-time
	// process creation with subject user + command line + token
	// elevation type. 4720/4722/4723/4725/4740 cover account lifecycle
	// (create, enable, password change, disable, lockout). 4768/4769
	// cover Kerberos TGT/TGS requests which are pivotal for golden /
	// silver ticket detection.
	winAuthQuery = `*[System[(` +
		`EventID=4624 or EventID=4625 or EventID=4634 or EventID=4647 or ` +
		`EventID=4672 or EventID=4688 or EventID=4698 or EventID=4702 or ` +
		`EventID=4720 or EventID=4722 or EventID=4723 or EventID=4725 or ` +
		`EventID=4740 or EventID=4768 or EventID=4769 or EventID=7045` +
		`)]]`
	// P1-13: save the bookmark to disk every 10 events instead of every
	// 100. The in-memory EvtUpdateBookmark already runs every event;
	// only the on-disk persistence cadence changes. Worst-case event
	// loss on hard crash drops from 99 events to 9, with negligible IO
	// (one ~600 byte atomic rename every ~10 events).
	winAuthBookmarkPersistEvery = 10
)

type winAuthState struct {
	mu           sync.Mutex
	result       windows.Handle
	bookmark     windows.Handle
	bookmarkPath string
	useSubscribe bool
	seenEvents   uint64
	primed       bool
}

// P2-14: per-collector winState replaces the legacy global map. The
// remaining package-level mutex is kept only for the rare integration
// tests that exercise getOrInitWindowsAuthState across multiple
// goroutines for the same collector; it serializes init only.
var _ sync.Mutex // retained as a placeholder to keep import minimal

func (s *winAuthState) closeAll() {
	if s == nil {
		return
	}
	kernel.EvtClose(s.result)
	kernel.EvtClose(s.bookmark)
	s.result = 0
	s.bookmark = 0
}

func authWindowsSecurityTelemetry(ac *AuthCollector) ([]Telemetry, error) {
	st, err := getOrInitWindowsAuthState(ac)
	if err != nil {
		return nil, err
	}
	return st.collect(ac)
}

// authWindowsStop releases the EvtSubscribe/EvtQuery result handle and
// the bookmark handle held by the per-collector state. Calling Stop
// multiple times is safe. P1-12, refactored for P2-14 to consult the
// per-collector field instead of the retired package-global map.
func authWindowsStop(ac *AuthCollector) {
	ac.winStateMu.Lock()
	st, _ := ac.winState.(*winAuthState)
	ac.winState = nil
	ac.winStateMu.Unlock()
	if st == nil {
		return
	}
	st.mu.Lock()
	if st.seenEvents > 0 && st.bookmark != 0 {
		_ = st.saveBookmarkAtomic()
	}
	st.closeAll()
	st.mu.Unlock()
}

func getOrInitWindowsAuthState(ac *AuthCollector) (*winAuthState, error) {
	ac.winStateMu.Lock()
	defer ac.winStateMu.Unlock()
	if st, ok := ac.winState.(*winAuthState); ok && st != nil {
		return st, nil
	}
	dataDir := ac.dataDir
	if strings.TrimSpace(dataDir) == "" {
		dataDir = "."
	}
	bmPath := filepath.Join(dataDir, "auth_bookmark.xml")
	st := &winAuthState{bookmarkPath: bmPath}
	if err := st.init(); err != nil {
		st.closeAll()
		return nil, err
	}
	ac.winState = st
	return st, nil
}

func (s *winAuthState) init() error {
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
	ch, _ := windows.UTF16PtrFromString(winAuthChannel)
	q, _ := windows.UTF16PtrFromString(winAuthQuery)

	// Prefer push style: subscribe to future events and read with EvtNext.
	if sub, err := kernel.EvtSubscribe(0, 0, ch, q, s.bookmark, 0, 0, kernel.EvtSubscribeToFutureEvents); err == nil {
		s.result = sub
		s.useSubscribe = true
		return nil
	}
	// Fallback poll query.
	rs, err := kernel.EvtQuery(nil, ch, q, kernel.EvtQueryChannelPath)
	if err != nil {
		return err
	}
	s.result = rs
	s.useSubscribe = false
	return nil
}

func (s *winAuthState) collect(ac *AuthCollector) ([]Telemetry, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.result == 0 {
		if err := s.init(); err != nil {
			return nil, err
		}
	}

	handles := make([]windows.Handle, 128)
	timeout := uint32(0)
	if !s.useSubscribe {
		timeout = 2000
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
			tel, parseErr := s.renderAndMap(ac, h)
			_ = kernel.EvtUpdateBookmark(s.bookmark, h)
			kernel.EvtClose(h)
			if parseErr != nil || tel == nil {
				continue
			}
			if !s.primed {
				// Missing/corrupt bookmark fallback: start from current stream position.
				continue
			}
			out = append(out, *tel)
			s.seenEvents++
			if s.seenEvents%winAuthBookmarkPersistEvery == 0 {
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

// saveBookmarkAtomic writes the current bookmark XML to a temp file via
// the Win32 EvtSaveBookmark API and atomically renames it over the
// canonical path. Two-step rename avoids leaving a partial file when
// the process dies mid-write.
//
// P1-13: kept as a single atomic-rename operation. The previous
// implementation read the temp file back and rewrote via
// writeBookmarkFile which doubled the IO; we now skip that copy and let
// EvtSaveBookmark write directly to the .tmp companion path.
func (s *winAuthState) saveBookmarkAtomic() error {
	tmp := s.bookmarkPath + ".tmp"
	tmpU16, err := windows.UTF16PtrFromString(tmp)
	if err != nil {
		return err
	}
	if err := kernel.EvtSaveBookmark(s.bookmark, tmpU16); err != nil {
		return err
	}
	return os.Rename(tmp, s.bookmarkPath)
}

func (s *winAuthState) renderAndMap(ac *AuthCollector, h windows.Handle) (*Telemetry, error) {
	buf := make([]uint16, 8192)
	used, _, err := kernel.EvtRender(0, h, kernel.EvtRenderEventXML, buf)
	if err != nil {
		if errno, ok := err.(windows.Errno); !ok || errno != windows.ERROR_INSUFFICIENT_BUFFER {
			return nil, err
		}
		nChars := int((used + 1) / 2)
		buf = make([]uint16, nChars)
		if _, _, err = kernel.EvtRender(0, h, kernel.EvtRenderEventXML, buf); err != nil {
			return nil, err
		}
	}
	xmlText := windows.UTF16ToString(buf)
	return mapSecurityEventXML(ac.endpointID, ac.hostname, xmlText), nil
}

type winEventXML struct {
	XMLName   xml.Name `xml:"Event"`
	System    struct {
		EventID     uint32 `xml:"EventID"`
		TimeCreated struct {
			SystemTime string `xml:"SystemTime,attr"`
		} `xml:"TimeCreated"`
	} `xml:"System"`
	EventData struct {
		Data []struct {
			Name  string `xml:"Name,attr"`
			Value string `xml:",chardata"`
		} `xml:"Data"`
	} `xml:"EventData"`
}

func mapSecurityEventXML(endpointID, hostname, xmlText string) *Telemetry {
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
		EndpointID:    endpointID,
		Timestamp:     ts,
		Hostname:      hostname,
		OS:            "windows",
	}

	switch ev.System.EventID {
	case 4624, 4625, 4672:
		base.EventType = schema.EventAuth
		ae := &schema.AuthEvent{
			BaseEvent:     base,
			EventID:       ev.System.EventID,
			SubjectUser:   fields["SubjectUserName"],
			SubjectDomain: fields["SubjectDomainName"],
			TargetUser:    fields["TargetUserName"],
			TargetDomain:  fields["TargetDomainName"],
			LogonType:     mapLogonType(fields["LogonType"]),
			LogonProcess:  fields["LogonProcessName"],
			AuthPackage:   fields["AuthenticationPackageName"],
			IpAddress:     fields["IpAddress"],
			IpPort:        fields["IpPort"],
			Workstation:   fields["WorkstationName"],
			LogonGuid:     fields["LogonGuid"],
			FailureReason: fields["FailureReason"],
			Status:        fields["Status"],
			SubStatus:     fields["SubStatus"],
			SubjectLogonID: fields["SubjectLogonId"],
			User:          firstNonEmpty(fields["TargetUserName"], fields["SubjectUserName"]),
			SourceIP:      fields["IpAddress"],
			Success:       ev.System.EventID == 4624 || ev.System.EventID == 4672,
			Privileged:    ev.System.EventID == 4672,
		}
		if p := strings.TrimSpace(fields["PrivilegeList"]); p != "" {
			parts := strings.Fields(strings.ReplaceAll(p, ",", " "))
			ae.PrivilegeListV = append([]string(nil), parts...)
			ae.PrivilegeList = strings.Join(parts, ",")
		}
		if ev.System.EventID == 4625 {
			ae.Success = false
		}
		if ae.Success {
			ae.Outcome = "success"
		} else {
			ae.Outcome = "failure"
		}
		ae.AuthType = "windows_security"
		return &Telemetry{Auth: ae}

	case 4634, 4647:
		// Logoff (4634) and user-initiated logoff (4647). Surface as an
		// AuthEvent with outcome=logoff so session-tracking detection
		// rules can correlate to a prior 4624.
		base.EventType = schema.EventAuth
		ae := &schema.AuthEvent{
			BaseEvent:      base,
			EventID:        ev.System.EventID,
			TargetUser:     fields["TargetUserName"],
			TargetDomain:   fields["TargetDomainName"],
			LogonType:      mapLogonType(fields["LogonType"]),
			SubjectLogonID: firstNonEmpty(fields["TargetLogonId"], fields["SubjectLogonId"]),
			User:           fields["TargetUserName"],
			AuthType:       "windows_security",
			Outcome:        "logoff",
			Success:        true,
		}
		return &Telemetry{Auth: ae}

	case 4688:
		// Real-time process creation. The payload contains the parent
		// (subject) account, the child image path, command line (when
		// command-line auditing is enabled), and the token elevation
		// type (1=default/limited, 2=elevated, 3=full).
		base.EventType = schema.EventProcess
		ae := &schema.AuthEvent{
			BaseEvent:      base,
			EventID:        ev.System.EventID,
			SubjectUser:    fields["SubjectUserName"],
			SubjectDomain:  fields["SubjectDomainName"],
			TargetUser:     fields["TargetUserName"],
			TargetDomain:   fields["TargetDomainName"],
			SubjectLogonID: fields["SubjectLogonId"],
			User:           firstNonEmpty(fields["SubjectUserName"]),
			AuthType:       "process_create",
			Outcome:        "success",
			Success:        true,
		}
		// Token elevation type lives in fields["TokenElevationType"].
		// Surface as Status so downstream consumers do not need a
		// schema bump for this single integer.
		if te := strings.TrimSpace(fields["TokenElevationType"]); te != "" {
			ae.Status = "TokenElevationType=" + te
		}
		return &Telemetry{Auth: ae}

	case 4720, 4722, 4723, 4725, 4740:
		// Account lifecycle: create / enable / password change /
		// disable / lockout. Surface as AuthEvent with operation
		// encoded in Outcome so detection rules can match without a
		// schema bump.
		base.EventType = schema.EventAuth
		op := map[uint32]string{
			4720: "account_create",
			4722: "account_enable",
			4723: "password_change",
			4725: "account_disable",
			4740: "account_lockout",
		}[ev.System.EventID]
		ae := &schema.AuthEvent{
			BaseEvent:     base,
			EventID:       ev.System.EventID,
			SubjectUser:   fields["SubjectUserName"],
			SubjectDomain: fields["SubjectDomainName"],
			TargetUser:    fields["TargetUserName"],
			TargetDomain:  fields["TargetDomainName"],
			User:          firstNonEmpty(fields["TargetUserName"], fields["SubjectUserName"]),
			AuthType:      "windows_security",
			Outcome:       op,
			Success:       true,
		}
		return &Telemetry{Auth: ae}

	case 4768, 4769:
		// Kerberos TGT (4768) and TGS (4769) requests. The 4768 fields
		// expose the requesting account; 4769 exposes the service
		// principal name. Both carry the client IP and the failure
		// status code which is the key signal for golden-ticket and
		// kerberoasting detection.
		base.EventType = schema.EventAuth
		ae := &schema.AuthEvent{
			BaseEvent: base,
			EventID:   ev.System.EventID,
			User:      firstNonEmpty(fields["TargetUserName"], fields["UserName"]),
			IpAddress: fields["IpAddress"],
			SourceIP:  fields["IpAddress"],
			IpPort:    fields["IpPort"],
			Status:    fields["Status"],
			AuthType:  "kerberos",
		}
		// 4769 carries ServiceName / ServiceSid that 4768 does not.
		if svc := strings.TrimSpace(fields["ServiceName"]); svc != "" {
			ae.LogonProcess = svc
		}
		ae.Success = strings.EqualFold(strings.TrimSpace(fields["Status"]), "0x0") ||
			strings.TrimSpace(fields["Status"]) == ""
		if ae.Success {
			ae.Outcome = "success"
		} else {
			ae.Outcome = "failure"
		}
		return &Telemetry{Auth: ae}

	case 4698, 4702:
		base.EventType = schema.EventProcess
		op := "created"
		if ev.System.EventID == 4702 {
			op = "modified"
		}
		return &Telemetry{Task: &schema.TaskEvent{
			BaseEvent:   base,
			EventID:     ev.System.EventID,
			SubjectUser: fields["SubjectUserName"],
			TaskName:    fields["TaskName"],
			TaskContent: firstNonEmpty(fields["TaskContent"], xmlText),
			Operation:   op,
		}}

	case 7045:
		base.EventType = schema.EventProcess
		return &Telemetry{Service: &schema.ServiceEvent{
			BaseEvent:    base,
			EventID:      ev.System.EventID,
			ServiceName:  fields["ServiceName"],
			ImagePath:    fields["ImagePath"],
			ServiceType:  fields["ServiceType"],
			StartType:    fields["StartType"],
			AccountName:  fields["AccountName"],
		}}
	default:
		return nil
	}
}

func mapLogonType(v string) string {
	n, err := strconv.Atoi(strings.TrimSpace(v))
	if err != nil {
		return strings.TrimSpace(v)
	}
	switch n {
	case 2:
		return "Interactive"
	case 3:
		return "Network"
	case 4:
		return "Batch"
	case 5:
		return "Service"
	case 7:
		return "Unlock"
	case 8:
		return "NetworkCleartext"
	case 9:
		return "NewCredentials"
	case 10:
		return "RemoteInteractive"
	default:
		return fmt.Sprintf("%d", n)
	}
}

func writeBookmarkFile(path string, content []byte) error {
	tmp := path + ".atomic"
	if err := os.WriteFile(tmp, content, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func readBookmarkFile(path string) ([]byte, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var v struct {
		XMLName xml.Name `xml:"BookmarkList"`
	}
	if err := xml.Unmarshal(b, &v); err != nil {
		return nil, err
	}
	return b, nil
}
