package main

import (
	"strings"
	"testing"
	"time"

	"github.com/razatechofficial/edr/internal/localapi"
)

// TestEvaluateUIState covers the screen decision. The point of each case is
// that a failed read is never rendered as "not enrolled": that was the defect,
// and it made an enrolled machine look unregistered to its own operator.
func TestEvaluateUIState(t *testing.T) {
	t.Parallel()

	enrolledRunning := localapi.PublicStatus{
		SchemaVersion: localapi.StatusFileSchemaVersion,
		Service:       localapi.ServiceRunning,
		Enrolled:      true,
		AgentID:       "agent-1",
		UpdatedAt:     time.Now().UTC(),
	}
	runningNotEnrolled := enrolledRunning
	runningNotEnrolled.Enrolled = false
	runningNotEnrolled.AgentID = ""
	stoppedButEnrolled := enrolledRunning
	stoppedButEnrolled.Service = localapi.ServiceStopped

	cases := []struct {
		name         string
		availability localapi.Availability
		status       localapi.PublicStatus
		wantState    uiState
		wantScreen   screen
	}{
		{
			name:         "enrolled and running shows the dashboard",
			availability: localapi.StatusOK,
			status:       enrolledRunning,
			wantState:    uiReady,
			wantScreen:   screenDashboard,
		},
		{
			name:         "running but unenrolled shows setup",
			availability: localapi.StatusOK,
			status:       runningNotEnrolled,
			wantState:    uiNotEnrolled,
			wantScreen:   screenSetup,
		},
		{
			name:         "a service the file reports stopped is not an enrollment problem",
			availability: localapi.StatusOK,
			status:       stoppedButEnrolled,
			wantState:    uiServiceStopped,
			wantScreen:   screenSetup,
		},
		{
			name:         "no status file means the agent is not running",
			availability: localapi.StatusMissing,
			wantState:    uiAgentNotRunning,
			wantScreen:   screenSetup,
		},
		{
			name:         "a stale status file means the agent stopped reporting",
			availability: localapi.StatusStale,
			status:       enrolledRunning,
			wantState:    uiAgentNotReporting,
			wantScreen:   screenSetup,
		},
		{
			name:         "a truncated status file is its own state",
			availability: localapi.StatusCorrupt,
			wantState:    uiStatusUnreadable,
			wantScreen:   screenSetup,
		},
		{
			name:         "a status file this account cannot open is its own state",
			availability: localapi.StatusUnreadable,
			wantState:    uiStatusUnreadable,
			wantScreen:   screenSetup,
		},
		{
			name:         "an unrecognised availability is not treated as healthy",
			availability: localapi.Availability("something new"),
			wantState:    uiStatusUnreadable,
			wantScreen:   screenSetup,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := evaluateUIState(tc.availability, tc.status)
			if got != tc.wantState {
				t.Fatalf("evaluateUIState(%q) = %q, want %q", tc.availability, got, tc.wantState)
			}
			if gotScreen := got.screen(); gotScreen != tc.wantScreen {
				t.Fatalf("%q.screen() = %q, want %q", got, gotScreen, tc.wantScreen)
			}
			if tc.wantState != uiReady && tc.wantState != uiNotEnrolled {
				// A read that failed must not claim anything about enrollment.
				if strings.Contains(strings.ToLower(got.headline()), "enroll") {
					t.Fatalf("%q headline blames enrollment for a status-file problem: %q", got, got.headline())
				}
			}
		})
	}
}

// TestUIStateMessagesAreUseful keeps every state explaining itself; a blank
// panel is how the previous version managed to say nothing true.
func TestUIStateMessagesAreUseful(t *testing.T) {
	t.Parallel()
	states := []uiState{
		uiReady, uiNotEnrolled, uiAgentNotRunning,
		uiAgentNotReporting, uiStatusUnreadable, uiServiceStopped,
	}
	seen := map[string]uiState{}
	for _, s := range states {
		if strings.TrimSpace(s.headline()) == "" {
			t.Fatalf("state %q has no headline", s)
		}
		if strings.TrimSpace(s.detail()) == "" {
			t.Fatalf("state %q has no detail", s)
		}
		if prev, dup := seen[s.headline()]; dup {
			t.Fatalf("states %q and %q share the headline %q", prev, s, s.headline())
		}
		seen[s.headline()] = s
	}
}

func TestServiceHealthyUsesTheSharedMapping(t *testing.T) {
	t.Parallel()
	// The macOS defect in one line: launchctl says "loaded", and the console
	// used to test for "running", "started" or "active".
	if !serviceHealthy(localapi.NormalizeServiceState("darwin", "loaded")) {
		t.Fatal("a loaded launchd job must read as healthy on macOS")
	}
	if !serviceHealthy(localapi.NormalizeServiceState("linux", "active")) {
		t.Fatal("an active systemd unit must read as healthy")
	}
	if !serviceHealthy(localapi.NormalizeServiceState("windows", "running")) {
		t.Fatal("a running Windows service must read as healthy")
	}
	for _, raw := range []string{"not loaded", "inactive", "stopped", ""} {
		if serviceHealthy(localapi.NormalizeServiceState("darwin", raw)) {
			t.Fatalf("%q must not read as healthy", raw)
		}
	}
}

func TestDescribeSourcesNamesBothSources(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name    string
		status  uiStatus
		wantAll []string
	}{
		{
			name: "connected socket",
			status: uiStatus{
				StatusFile:   "/run/edr-agent/status.json",
				Availability: localapi.StatusOK,
				Control:      controlOK,
			},
			wantAll: []string{"/run/edr-agent/status.json", "ok", "connected"},
		},
		{
			name: "socket this account may not open",
			status: uiStatus{
				StatusFile:    "/run/edr-agent/status.json",
				Availability:  localapi.StatusOK,
				Control:       controlDenied,
				ControlDetail: "permission denied",
			},
			wantAll: []string{"not readable by this account", "permission denied"},
		},
		{
			name: "missing status file and no socket",
			status: uiStatus{
				StatusFile:   "/run/edr-agent/status.json",
				Availability: localapi.StatusMissing,
				Control:      controlUnreachable,
			},
			wantAll: []string{"missing", "unreachable"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := describeSources(tc.status)
			for _, want := range tc.wantAll {
				if !strings.Contains(got, want) {
					t.Fatalf("describeSources() = %q, must mention %q", got, want)
				}
			}
		})
	}
}

func TestDashPlaceholder(t *testing.T) {
	t.Parallel()
	if dash("  ") != "—" {
		t.Fatal("blank values must render as a placeholder, not as an empty field")
	}
	if dash(" running ") != "running" {
		t.Fatal("dash must trim")
	}
}
