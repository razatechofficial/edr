//go:build windows

package collector

import (
	"strings"
	"testing"
)

func TestMapLogTargetEventXML_ProcessShape(t *testing.T) {
	t.Parallel()
	xmlText := `<Event>
  <System>
    <EventID>7045</EventID>
    <TimeCreated SystemTime="2026-05-06T10:11:12.0000000Z"/>
  </System>
  <EventData>
    <Data Name="ProcessId">4321</Data>
    <Data Name="ServiceName">BadSvc</Data>
  </EventData>
</Event>`
	tel := mapLogTargetEventXML("ep1", "host1", "System", xmlText, false)
	if tel == nil || tel.Process == nil {
		t.Fatalf("expected process telemetry, got %#v", tel)
	}
	if tel.Process.ProcessName != "log_target_eventchannel" {
		t.Fatalf("process_name=%q", tel.Process.ProcessName)
	}
	if tel.Process.PID != 4321 {
		t.Fatalf("pid=%d want 4321", tel.Process.PID)
	}
	if tel.Process.ProcessPath != "System" {
		t.Fatalf("path=%q", tel.Process.ProcessPath)
	}
	if tel.Process.CommandLine == "" {
		t.Fatalf("missing command line %#v", tel.Process)
	}
	found := false
	for _, tag := range tel.Process.Tags {
		if tag == "eventchannel" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("missing eventchannel tag: %#v", tel.Process.Tags)
	}
}

func TestPowerShellDefenderChannels_BookmarksUniqueAndXML(t *testing.T) {
	t.Parallel()
	seen := map[string]struct{}{}
	for _, ch := range pwshDefenderChannels {
		if strings.TrimSpace(ch.bookmark) == "" {
			t.Fatalf("empty bookmark for channel %q", ch.name)
		}
		if !strings.HasSuffix(strings.ToLower(ch.bookmark), ".xml") {
			t.Fatalf("bookmark %q must be .xml", ch.bookmark)
		}
		if _, ok := seen[ch.bookmark]; ok {
			t.Fatalf("duplicate bookmark name %q", ch.bookmark)
		}
		seen[ch.bookmark] = struct{}{}
	}
}

