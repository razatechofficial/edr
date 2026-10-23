package agent

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/razatechofficial/edr/internal/config"
	"github.com/razatechofficial/edr/internal/localapi"
	"github.com/razatechofficial/edr/internal/xdrclient"
)

func newTestLocalControl(t *testing.T, a *Agent) *localControl {
	t.Helper()
	if a.logger == nil {
		a.logger = slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	}
	return &localControl{
		agent:           a,
		startedAt:       time.Now().Add(-time.Minute),
		isolationMarker: a.localIsolationMarkerPath(),
	}
}

func TestLocalControlEnrollment(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name         string
		configID     string
		state        xdrclient.State
		wantEnrolled bool
		wantAgentID  string
		wantIngest   string
	}{
		{
			name:         "enrolled with ingest hosts",
			state:        xdrclient.State{AgentID: "agent-1", IngestHosts: []string{"a:443", "b:443"}},
			wantEnrolled: true,
			wantAgentID:  "agent-1",
			wantIngest:   "a:443,b:443",
		},
		{
			// A local identity with nowhere to send telemetry is not an
			// enrollment, and reporting it as one is how an agent looks
			// healthy while sending nothing.
			name:        "local id without ingest hosts is not enrolled",
			configID:    "local-uuid",
			wantAgentID: "local-uuid",
		},
		{
			name: "no identity at all",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var cfg config.Config
			cfg.Agent.ID = tc.configID
			ctrl := newTestLocalControl(t, &Agent{cfg: cfg, xdrState: tc.state})

			got := ctrl.Enrollment(context.Background())
			if got.Enrolled != tc.wantEnrolled {
				t.Fatalf("Enrolled = %v, want %v", got.Enrolled, tc.wantEnrolled)
			}
			if got.AgentID != tc.wantAgentID {
				t.Fatalf("AgentID = %q, want %q", got.AgentID, tc.wantAgentID)
			}
			if got.IngestHost != tc.wantIngest {
				t.Fatalf("IngestHost = %q, want %q", got.IngestHost, tc.wantIngest)
			}
		})
	}
}

func TestLocalControlStatus(t *testing.T) {
	t.Parallel()
	var cfg config.Config
	cfg.Agent.Version = "3.4.5"
	a := &Agent{cfg: cfg}
	a.localAlerts.Add(4)
	ctrl := newTestLocalControl(t, a)

	st := ctrl.Status(context.Background())
	if st.Status != "running" {
		t.Fatalf("Status = %q, want running", st.Status)
	}
	if st.Version != "3.4.5" {
		t.Fatalf("Version = %q, want 3.4.5", st.Version)
	}
	if st.PID != os.Getpid() {
		t.Fatalf("PID = %d, want %d", st.PID, os.Getpid())
	}
	if st.OS != runtime.GOOS || st.Arch != runtime.GOARCH {
		t.Fatalf("OS/Arch = %s/%s, want %s/%s", st.OS, st.Arch, runtime.GOOS, runtime.GOARCH)
	}
	if st.AlertsGenerated != 4 {
		t.Fatalf("AlertsGenerated = %d, want 4", st.AlertsGenerated)
	}
	if st.Uptime == "" || st.StartedAt.IsZero() {
		t.Fatalf("uptime must be reported: uptime=%q started_at=%v", st.Uptime, st.StartedAt)
	}
	if st.MemoryMB <= 0 {
		t.Fatalf("MemoryMB = %v, want a positive reading", st.MemoryMB)
	}
	if st.CPUPercent < 0 || st.CPUPercent > 100 {
		t.Fatalf("CPUPercent = %v, want 0..100", st.CPUPercent)
	}
}

func TestLocalIsolationMarkerRoundTrip(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	var cfg config.Config
	cfg.Agent.DataDir = dir
	ctrl := newTestLocalControl(t, &Agent{cfg: cfg})

	if ctrl.isolated() {
		t.Fatal("a fresh agent must not report itself isolated")
	}
	ctrl.setLocalIsolation(true)
	if !ctrl.isolated() {
		t.Fatal("isolation must be visible after it is recorded")
	}
	marker := filepath.Join(dir, "response", "local_isolation")
	if _, err := os.Stat(marker); err != nil {
		t.Fatalf("isolation marker not written: %v", err)
	}
	// Clearing twice must not fail: release is idempotent.
	ctrl.setLocalIsolation(false)
	ctrl.setLocalIsolation(false)
	if ctrl.isolated() {
		t.Fatal("isolation must be cleared after release")
	}
}

// TestStatusFileCarriesNoAgentSecret is the end-to-end form of the invariant:
// an agent holding a bootstrap token, TLS paths and a callback token must
// publish none of them in the world-readable status file.
func TestStatusFileCarriesNoAgentSecret(t *testing.T) {
	t.Parallel()
	const token = "bootstrap-token-do-not-publish"

	var cfg config.Config
	cfg.Agent.ID = "agent-99"
	cfg.Agent.Version = "1.0.0"
	cfg.Agent.DataDir = t.TempDir()
	cfg.XDR.EnrollmentToken = token
	cfg.Response.Approval.CallbackToken = "callback-token-do-not-publish"
	cfg.Server.TLSKeyPath = "/etc/edr-agent/tls/agent.key"

	a := &Agent{cfg: cfg, xdrState: xdrclient.State{
		AgentID:        "agent-99",
		IngestHosts:    []string{"ingest:443"},
		CertificatePEM: "-----BEGIN CERTIFICATE-----secret-----END CERTIFICATE-----",
	}}
	ctrl := newTestLocalControl(t, a)

	path := filepath.Join(cfg.Agent.DataDir, "status.json")
	public := localapi.PublicFrom(
		ctrl.Status(context.Background()),
		ctrl.Enrollment(context.Background()),
		localapi.ServiceRunning,
	)
	if err := localapi.WriteStatusFile(path, public); err != nil {
		t.Fatalf("WriteStatusFile: %v", err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read status file: %v", err)
	}
	body := string(raw)
	for _, secret := range []string{
		token,
		"callback-token-do-not-publish",
		"agent.key",
		"BEGIN CERTIFICATE",
	} {
		if strings.Contains(body, secret) {
			t.Fatalf("status file leaked %q:\n%s", secret, body)
		}
	}
	if !strings.Contains(body, "agent-99") || !strings.Contains(body, "ingest:443") {
		t.Fatalf("status file must still carry the non-secret identifiers:\n%s", body)
	}
}

func TestUpdateRulesWithoutAnEngineIsUnavailable(t *testing.T) {
	t.Parallel()
	ctrl := newTestLocalControl(t, &Agent{})
	if _, err := ctrl.UpdateRules(context.Background()); err == nil {
		t.Fatal("rules update must fail when no detection engine is loaded")
	} else if !strings.Contains(err.Error(), "subsystem unavailable") {
		t.Fatalf("error = %v, want an unavailable-subsystem error", err)
	}
}

func TestResponseOpsWithoutAnEngineAreUnavailable(t *testing.T) {
	t.Parallel()
	ctrl := newTestLocalControl(t, &Agent{})
	for name, run := range map[string]func(context.Context) (string, error){
		"isolate":   ctrl.Isolate,
		"release":   ctrl.Release,
		"forensics": ctrl.CollectForensics,
	} {
		if _, err := run(context.Background()); err == nil {
			t.Fatalf("%s must fail when the response engine is disabled", name)
		} else if !strings.Contains(err.Error(), "response engine is disabled") {
			t.Fatalf("%s error = %v, want a disabled-response-engine error", name, err)
		}
	}
}
