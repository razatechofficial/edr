//go:build windows

package collector

import (
	"strings"
	"testing"
)

func TestPwshChannelStateSaveBookmarkAtomic_NoHandleNoPath(t *testing.T) {
	t.Parallel()
	st := &pwshChannelState{}
	if err := st.saveBookmarkAtomic(); err != nil {
		t.Fatalf("expected nil for noop save, got %v", err)
	}
}

func TestMapDefenderEventXML_FieldDepth(t *testing.T) {
	t.Parallel()
	xml := `<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <EventID>1116</EventID>
    <TimeCreated SystemTime="2024-01-02T15:04:05.0000000Z"/>
  </System>
  <EventData>
    <Data Name="Threat Name">EICAR_Test</Data>
    <Data Name="Threat ID">2147519003</Data>
    <Data Name="Detection Source">Local</Data>
    <Data Name="Path">C:\temp\eicar.com</Data>
    <Data Name="Process Name">MsMpEng.exe</Data>
    <Data Name="User">NT AUTHORITY\SYSTEM</Data>
    <Data Name="Action Name">Quarantine</Data>
  </EventData>
</Event>`
	tel := mapDefenderEventXML("ep1", "host1", xml)
	if tel == nil || tel.Process == nil {
		t.Fatal("expected process telemetry")
	}
	pe := tel.Process
	if !strings.Contains(pe.CommandLine, "threat=EICAR_Test") {
		t.Fatalf("command line missing threat: %q", pe.CommandLine)
	}
	if !strings.Contains(pe.CommandLine, "threat_id=2147519003") {
		t.Fatalf("command line missing threat_id: %q", pe.CommandLine)
	}
	if pe.ProcessPath != `C:\temp\eicar.com` {
		t.Fatalf("process_path: got %q", pe.ProcessPath)
	}
	if pe.User != `NT AUTHORITY\SYSTEM` {
		t.Fatalf("user: got %q", pe.User)
	}
}

func TestMapAppLockerEventXML_FieldDepth(t *testing.T) {
	t.Parallel()
	xml := `<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <EventID>8004</EventID>
    <TimeCreated SystemTime="2024-01-02T15:04:05.0000000Z"/>
  </System>
  <EventData>
    <Data Name="PolicyName">EXE policy</Data>
    <Data Name="RuleName">Deny risky</Data>
    <Data Name="FullFilePath">C:\Apps\bad.exe</Data>
    <Data Name="Fqbn">O=MICROSOFT, L=REDMOND</Data>
    <Data Name="TargetUser">DOMAIN\alice</Data>
    <Data Name="FileHash">deadbeef</Data>
    <Data Name="TargetProcessId">1234</Data>
  </EventData>
</Event>`
	tel := mapAppLockerEventXML("ep1", "host1", xml)
	if tel == nil || tel.Process == nil {
		t.Fatal("expected process telemetry")
	}
	pe := tel.Process
	if pe.PID != 1234 {
		t.Fatalf("pid: got %d", pe.PID)
	}
	if !strings.Contains(pe.CommandLine, "policy=EXE policy") || !strings.Contains(pe.CommandLine, "rule=Deny risky") {
		t.Fatalf("command line: %q", pe.CommandLine)
	}
	if pe.User != `DOMAIN\alice` {
		t.Fatalf("user: got %q", pe.User)
	}
}
