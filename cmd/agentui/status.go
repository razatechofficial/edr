package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/razatechofficial/edr/internal/localapi"
)

// The console runs as the logged-in user. It therefore cannot read the agent
// config (0640 in a 0750 directory) or the enrollment state (0600 in a 0700
// one), which is why every field here used to read negative on a healthy
// enrolled agent: the probe failed and a failed probe was rendered as
// "not enrolled" with a blank agent id.
//
// Everything on the read-only view now comes from the world-readable status
// file the agent publishes. The control socket is consulted for live fields
// only, and the socket is root:edr, so not reaching it is the normal case for
// an unprivileged console and is shown as its own state rather than as a
// fault.

// controlState names how the live control socket answered.
type controlState string

const (
	// controlOK means the socket answered.
	controlOK controlState = "ok"
	// controlDenied means the socket exists but this account may not open it.
	// That is the expected result for an unprivileged console.
	controlDenied controlState = "denied"
	// controlUnreachable means there was nothing to connect to.
	controlUnreachable controlState = "unreachable"
)

// uiState is the one named state the whole window is rendered from. Each
// value has exactly one cause, so a stopped agent, an agent that stopped
// reporting, an unreadable status file and an unenrolled agent are four
// different things on screen instead of one wrong thing.
type uiState string

const (
	// uiReady means enrolled and running: show the dashboard.
	uiReady uiState = "ready"
	// uiNotEnrolled means the agent is running and has no platform identity.
	uiNotEnrolled uiState = "not-enrolled"
	// uiAgentNotRunning means no status file exists.
	uiAgentNotRunning uiState = "agent-not-running"
	// uiAgentNotReporting means the status file is stale: the agent stopped
	// without clearing it, or it is wedged.
	uiAgentNotReporting uiState = "agent-not-reporting"
	// uiStatusUnreadable means the status file is present but could not be
	// read or parsed.
	uiStatusUnreadable uiState = "status-unreadable"
	// uiServiceStopped means the status file reports a service that is not
	// running.
	uiServiceStopped uiState = "service-stopped"
)

// screen is which of the two views the window shows.
type screen string

const (
	screenSetup     screen = "setup"
	screenDashboard screen = "dashboard"
)

// screen returns the view for this state. Only a running, enrolled agent gets
// the dashboard; everything else gets setup, which is where the enrollment
// token and the service controls are.
func (s uiState) screen() screen {
	if s == uiReady {
		return screenDashboard
	}
	return screenSetup
}

// headline is the one-line explanation shown at the top of the setup view.
func (s uiState) headline() string {
	switch s {
	case uiReady:
		return "Protected"
	case uiNotEnrolled:
		return "Not enrolled"
	case uiAgentNotRunning:
		return "Agent not running"
	case uiAgentNotReporting:
		return "Agent not reporting"
	case uiStatusUnreadable:
		return "Agent status unreadable"
	case uiServiceStopped:
		return "Service stopped"
	default:
		return "Unknown state"
	}
}

// detail says what to do about the state.
func (s uiState) detail() string {
	switch s {
	case uiReady:
		return "The sensor is running and enrolled with the XDR platform."
	case uiNotEnrolled:
		return "The sensor is running but has no platform identity. Paste an enrollment token below to register this device."
	case uiAgentNotRunning:
		return "The sensor has not published a status file since this host booted. Start it below, then refresh."
	case uiAgentNotReporting:
		return "The sensor's last status is too old to trust. It has stopped or is wedged; start it below, then refresh."
	case uiStatusUnreadable:
		return "A status file exists but could not be read. The install may be partial or the file may be truncated."
	case uiServiceStopped:
		return "The service manager reports the sensor as stopped. Start it below, then refresh."
	default:
		return "The agent state could not be determined."
	}
}

// uiStatus is everything the window renders.
type uiStatus struct {
	State        uiState
	Availability localapi.Availability
	Service      localapi.ServiceState
	Enrolled     bool
	AgentID      string
	Ingest       string
	Version      string
	Uptime       string
	Detections   uint64
	Isolated     bool
	// Runtime is the agent's own word for its state, from the control socket.
	Runtime       string
	Control       controlState
	ControlDetail string
	UpdatedAt     time.Time
	StatusFile    string
	Error         string
}

// evaluateUIState maps the status file and its availability to one named UI
// state. It is the only place the screen decision is made, and it never
// consults an exec result: a probe that failed says nothing about enrollment.
func evaluateUIState(availability localapi.Availability, st localapi.PublicStatus) uiState {
	switch availability {
	case localapi.StatusMissing:
		return uiAgentNotRunning
	case localapi.StatusStale:
		return uiAgentNotReporting
	case localapi.StatusUnreadable, localapi.StatusCorrupt:
		return uiStatusUnreadable
	case localapi.StatusOK:
		if !st.Service.Healthy() {
			return uiServiceStopped
		}
		if !st.Enrolled {
			return uiNotEnrolled
		}
		return uiReady
	default:
		return uiStatusUnreadable
	}
}

// loadStatus reads the status file, then tries the control socket for live
// fields. It is safe to call off the UI goroutine and does no network I/O.
func loadStatus() uiStatus {
	path := localapi.DefaultStatusFile()
	public, availability, readErr := localapi.ReadStatusFile(path, 0)

	st := uiStatus{
		Availability: availability,
		StatusFile:   path,
		Control:      controlUnreachable,
		State:        evaluateUIState(availability, public),
		UpdatedAt:    public.UpdatedAt,
	}
	if readErr != nil && availability != localapi.StatusMissing {
		st.Error = readErr.Error()
	}
	switch availability {
	case localapi.StatusOK, localapi.StatusStale:
		st.Service = public.Service
		st.Enrolled = public.Enrolled
		st.AgentID = public.AgentID
		st.Ingest = public.IngestHost
		st.Version = public.Version
		st.Uptime = public.Uptime
		st.Detections = public.Detections
		st.Isolated = public.Isolated
	default:
		st.Service = localapi.ServiceUnknown
	}

	live, control, detail := fetchLiveStatus()
	st.Control, st.ControlDetail = control, detail
	if control == controlOK {
		st.Runtime = live.Status
		if live.Version != "" {
			st.Version = live.Version
		}
		if live.Uptime != "" {
			st.Uptime = live.Uptime
		}
		st.Detections = live.AlertsGenerated
		st.Isolated = live.Isolated
	}
	return st
}

// fetchLiveStatus asks the control socket for the live counters. It is
// expected to fail for an unprivileged console: the socket is root:edr, so
// "denied" is a normal answer and not an error to show as a fault.
func fetchLiveStatus() (localapi.Status, controlState, string) {
	socket := localapi.DefaultSocketPath()
	if socket == "" {
		return localapi.Status{}, controlUnreachable, "no control socket on this platform"
	}
	if _, err := os.Stat(socket); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return localapi.Status{}, controlUnreachable, "the agent is not serving a control socket"
		}
		return localapi.Status{}, controlDenied, err.Error()
	}
	client := &http.Client{
		Timeout: 3 * time.Second,
		Transport: &http.Transport{
			DialContext: func(_ context.Context, _, _ string) (net.Conn, error) {
				return net.DialTimeout("unix", socket, 2*time.Second)
			},
		},
	}
	resp, err := client.Get("http://localhost/api/v1/status")
	if err != nil {
		state := controlUnreachable
		if errors.Is(err, fs.ErrPermission) {
			state = controlDenied
		}
		return localapi.Status{}, state, err.Error()
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return localapi.Status{}, controlUnreachable, err.Error()
	}
	if resp.StatusCode >= 400 {
		return localapi.Status{}, controlDenied,
			fmt.Sprintf("HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	var live localapi.Status
	if err := json.Unmarshal(body, &live); err != nil {
		return localapi.Status{}, controlUnreachable, err.Error()
	}
	return live, controlOK, ""
}

func friendlyExecError(err error) string {
	msg := err.Error()
	if strings.Contains(msg, "Bad CPU type") || strings.Contains(msg, "exec format error") {
		return "This installer does not match this Mac. On Apple Silicon download the arm64 package; on Intel download amd64."
	}
	var execErr *exec.Error
	if errors.As(err, &execErr) && errors.Is(execErr.Err, exec.ErrNotFound) {
		return "edrctl was not found. Reinstall EDR Agent."
	}
	return msg
}

func dash(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return "—"
	}
	return s
}

// serviceHealthy reports whether a service state means the sensor is up.
//
// It used to match "running", "started" or "active" against the raw output of
// whichever service manager the host runs. launchctl says "loaded", so a
// healthy macOS agent read as unhealthy. The per-OS mapping now lives in one
// place.
func serviceHealthy(s localapi.ServiceState) bool { return s.Healthy() }
