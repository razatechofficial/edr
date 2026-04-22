//go:build windows

package collector

import (
	"path/filepath"
	"testing"
)

func TestMapLogonType(t *testing.T) {
	cases := map[string]string{
		"2":  "Interactive",
		"3":  "Network",
		"4":  "Batch",
		"5":  "Service",
		"7":  "Unlock",
		"8":  "NetworkCleartext",
		"9":  "NewCredentials",
		"10": "RemoteInteractive",
		"99": "99",
	}
	for in, want := range cases {
		if got := mapLogonType(in); got != want {
			t.Fatalf("mapLogonType(%q) got %q want %q", in, got, want)
		}
	}
}

func TestMapSecurityEventXML_4624(t *testing.T) {
	raw := `<Event><System><EventID>4624</EventID><TimeCreated SystemTime="2026-01-01T00:00:00.0000000Z"/></System><EventData>
<Data Name="SubjectUserName">SYSTEM</Data><Data Name="SubjectDomainName">NT AUTHORITY</Data>
<Data Name="TargetUserName">alice</Data><Data Name="TargetDomainName">CONTOSO</Data>
<Data Name="LogonType">3</Data><Data Name="LogonProcessName">NtLmSsp </Data>
<Data Name="AuthenticationPackageName">NTLM</Data><Data Name="IpAddress">10.0.0.1</Data>
<Data Name="IpPort">51524</Data><Data Name="WorkstationName">WS1</Data>
<Data Name="LogonGuid">{1234}</Data></EventData></Event>`
	tel := mapSecurityEventXML("ep", "host", raw)
	if tel == nil || tel.Auth == nil {
		t.Fatal("expected auth telemetry")
	}
	if !tel.Auth.Success || tel.Auth.TargetUser != "alice" || tel.Auth.LogonType != "Network" {
		t.Fatalf("unexpected auth: %+v", tel.Auth)
	}
}

func TestMapSecurityEventXML_4625(t *testing.T) {
	raw := `<Event><System><EventID>4625</EventID><TimeCreated SystemTime="2026-01-01T00:00:00.0000000Z"/></System><EventData>
<Data Name="SubjectUserName">SYSTEM</Data><Data Name="TargetUserName">bob</Data>
<Data Name="FailureReason">Unknown user name or bad password.</Data>
<Data Name="Status">0xC000006D</Data><Data Name="SubStatus">0xC000006A</Data></EventData></Event>`
	tel := mapSecurityEventXML("ep", "host", raw)
	if tel == nil || tel.Auth == nil {
		t.Fatal("expected auth telemetry")
	}
	if tel.Auth.Success || tel.Auth.FailureReason == "" || tel.Auth.Status == "" || tel.Auth.SubStatus == "" {
		t.Fatalf("unexpected failure auth: %+v", tel.Auth)
	}
}

func TestMapSecurityEventXML_4672(t *testing.T) {
	raw := `<Event><System><EventID>4672</EventID><TimeCreated SystemTime="2026-01-01T00:00:00.0000000Z"/></System><EventData>
<Data Name="SubjectUserName">svc</Data><Data Name="SubjectDomainName">DOM</Data>
<Data Name="SubjectLogonId">0x123</Data><Data Name="PrivilegeList">SeDebugPrivilege SeTcbPrivilege</Data></EventData></Event>`
	tel := mapSecurityEventXML("ep", "host", raw)
	if tel == nil || tel.Auth == nil {
		t.Fatal("expected auth telemetry")
	}
	if !tel.Auth.Privileged || len(tel.Auth.PrivilegeListV) != 2 {
		t.Fatalf("unexpected privileged auth: %+v", tel.Auth)
	}
}

func TestMapSecurityEventXML_4698_4702_7045(t *testing.T) {
	taskCreate := `<Event><System><EventID>4698</EventID><TimeCreated SystemTime="2026-01-01T00:00:00.0000000Z"/></System><EventData>
<Data Name="SubjectUserName">alice</Data><Data Name="TaskName">\Foo\Bar</Data><Data Name="TaskContent"><![CDATA[<Task/>]]></Data></EventData></Event>`
	taskModify := `<Event><System><EventID>4702</EventID><TimeCreated SystemTime="2026-01-01T00:00:00.0000000Z"/></System><EventData>
<Data Name="SubjectUserName">alice</Data><Data Name="TaskName">\Foo\Bar</Data><Data Name="TaskContent"><![CDATA[<TaskV2/>]]></Data></EventData></Event>`
	service := `<Event><System><EventID>7045</EventID><TimeCreated SystemTime="2026-01-01T00:00:00.0000000Z"/></System><EventData>
<Data Name="ServiceName">svc1</Data><Data Name="ImagePath">C:\svc.exe</Data><Data Name="ServiceType">user mode service</Data><Data Name="StartType">auto start</Data><Data Name="AccountName">LocalSystem</Data></EventData></Event>`

	if tel := mapSecurityEventXML("ep", "host", taskCreate); tel == nil || tel.Task == nil || tel.Task.Operation != "created" {
		t.Fatalf("expected created task, got %+v", tel)
	}
	if tel := mapSecurityEventXML("ep", "host", taskModify); tel == nil || tel.Task == nil || tel.Task.Operation != "modified" {
		t.Fatalf("expected modified task, got %+v", tel)
	}
	if tel := mapSecurityEventXML("ep", "host", service); tel == nil || tel.Service == nil || tel.Service.ServiceName != "svc1" {
		t.Fatalf("expected service event, got %+v", tel)
	}
}

func TestBookmarkFileRoundTrip(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "auth_bookmark.xml")
	b := []byte(`<BookmarkList><Bookmark Channel='Security' RecordId='1' IsCurrent='true'/></BookmarkList>`)
	if err := writeBookmarkFile(p, b); err != nil {
		t.Fatal(err)
	}
	got, err := readBookmarkFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(b) {
		t.Fatalf("bookmark mismatch got %q want %q", string(got), string(b))
	}
}
