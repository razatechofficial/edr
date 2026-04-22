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
	winAuthQuery   = "*[System[(EventID=4624 or EventID=4625 or EventID=4672 or EventID=4698 or EventID=4702 or EventID=7045)]]"
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

var (
	winAuthStatesMu sync.Mutex
	winAuthStates   = map[*AuthCollector]*winAuthState{}
)

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

func getOrInitWindowsAuthState(ac *AuthCollector) (*winAuthState, error) {
	winAuthStatesMu.Lock()
	defer winAuthStatesMu.Unlock()
	if st := winAuthStates[ac]; st != nil {
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
	winAuthStates[ac] = st
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
			if s.seenEvents%100 == 0 {
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

func (s *winAuthState) saveBookmarkAtomic() error {
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
