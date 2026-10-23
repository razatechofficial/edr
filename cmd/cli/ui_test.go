package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/razatechofficial/edr/internal/localapi"
)

// TestEnrollmentSnapshotFromStatusFile covers the permissions defect: an
// unprivileged caller cannot read the 0640 config or the 0600 enrollment
// state, so enrollment has to come from the published status file.
func TestEnrollmentSnapshotFromStatusFile(t *testing.T) {
	cases := []struct {
		name         string
		write        *localapi.PublicStatus
		raw          string
		wantEnrolled bool
		wantAgentID  string
		wantIngest   string
	}{
		{
			name: "a fresh status file is authoritative",
			write: &localapi.PublicStatus{
				Service:    localapi.ServiceRunning,
				Enrolled:   true,
				AgentID:    "agent-42",
				IngestHost: "ingest-a:443,ingest-b:443",
			},
			wantEnrolled: true,
			wantAgentID:  "agent-42",
			wantIngest:   "ingest-a:443,ingest-b:443",
		},
		{
			name: "a stale status file still names the agent",
			write: &localapi.PublicStatus{
				Service:   localapi.ServiceRunning,
				Enrolled:  true,
				AgentID:   "agent-43",
				UpdatedAt: time.Now().UTC().Add(-24 * time.Hour),
			},
			wantEnrolled: true,
			wantAgentID:  "agent-43",
		},
		{
			name: "an unenrolled agent reports itself unenrolled",
			write: &localapi.PublicStatus{
				Service:  localapi.ServiceRunning,
				Enrolled: false,
			},
		},
		{
			// Falls through to the on-disk path, which finds nothing in this
			// test because configFile does not exist.
			name: "a truncated status file is not trusted",
			raw:  `{"schema_version":1,"agent_i`,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "status.json")
			switch {
			case tc.write != nil:
				if err := localapi.WriteStatusFile(path, *tc.write); err != nil {
					t.Fatalf("seed status file: %v", err)
				}
			case tc.raw != "":
				if err := writeRaw(path, tc.raw); err != nil {
					t.Fatalf("seed raw status file: %v", err)
				}
			}

			// enrollmentSnapshotFromDisk reads this package-level path.
			prev := configFile
			configFile = filepath.Join(dir, "no-such-config.yaml")
			t.Cleanup(func() { configFile = prev })

			enrolled, agentID, ingest := enrollmentSnapshotFrom(path)
			if enrolled != tc.wantEnrolled {
				t.Fatalf("enrolled = %v, want %v", enrolled, tc.wantEnrolled)
			}
			if agentID != tc.wantAgentID {
				t.Fatalf("agentID = %q, want %q", agentID, tc.wantAgentID)
			}
			if ingest != tc.wantIngest {
				t.Fatalf("ingest = %q, want %q", ingest, tc.wantIngest)
			}
		})
	}
}

func TestServiceRuntimeStatusIsCanonical(t *testing.T) {
	t.Parallel()
	// Whatever this host's service manager says, the CLI reports one of the
	// canonical states, so no caller has to match substrings again.
	got := serviceRuntimeStatus()
	switch got {
	case localapi.ServiceRunning, localapi.ServiceStarting, localapi.ServiceStopped,
		localapi.ServiceNotInstalled, localapi.ServiceUnknown:
	default:
		t.Fatalf("serviceRuntimeStatus() = %q, which is not a canonical state", got)
	}
}

func writeRaw(path, body string) error {
	return os.WriteFile(path, []byte(body), 0o644)
}
