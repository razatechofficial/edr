package localapi

import "testing"

func TestNormalizeServiceState(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		goos string
		raw  string
		want ServiceState
	}{
		// The defect: launchctl reports a loaded job and the console tested
		// for "running", "started" or "active", so every healthy macOS agent
		// read as unhealthy.
		{"darwin loaded is running", "darwin", "loaded", ServiceRunning},
		{"darwin loaded is healthy regardless of case", "darwin", "Loaded", ServiceRunning},
		{"darwin state line running", "darwin", "running", ServiceRunning},
		{"darwin not loaded", "darwin", "not loaded", ServiceNotInstalled},
		{"darwin waiting", "darwin", "waiting", ServiceStarting},
		{"darwin not running", "darwin", "not running", ServiceStopped},

		{"linux active", "linux", "active", ServiceRunning},
		{"linux activating", "linux", "activating", ServiceStarting},
		{"linux inactive", "linux", "inactive", ServiceStopped},
		{"linux failed", "linux", "failed", ServiceStopped},
		{"linux no such unit", "linux", "not-found", ServiceNotInstalled},
		{"linux unknown stays unread", "linux", "unknown", ServiceUnknown},
		{"linux trims systemctl newline", "linux", "active\n", ServiceRunning},

		{"windows running", "windows", "running", ServiceRunning},
		{"windows start pending", "windows", "start_pending", ServiceStarting},
		{"windows stopped", "windows", "stopped", ServiceStopped},
		{"windows installed is unread not negative", "windows", "installed", ServiceUnknown},
		{"windows not installed", "windows", "not installed", ServiceNotInstalled},

		{"empty is unknown", "linux", "", ServiceUnknown},
		{"unrecognised is unknown", "linux", "banana", ServiceUnknown},
		{"unknown goos falls back to canonical names", "plan9", "running", ServiceRunning},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := NormalizeServiceState(tc.goos, tc.raw); got != tc.want {
				t.Fatalf("NormalizeServiceState(%q, %q) = %q, want %q", tc.goos, tc.raw, got, tc.want)
			}
		})
	}
}

func TestNormalizeServiceStateIsIdempotent(t *testing.T) {
	t.Parallel()
	for _, goos := range []string{"linux", "darwin", "windows"} {
		for _, st := range []ServiceState{ServiceRunning, ServiceStarting, ServiceStopped, ServiceNotInstalled, ServiceUnknown} {
			if got := NormalizeServiceState(goos, string(st)); got != st {
				t.Fatalf("NormalizeServiceState(%q, %q) = %q, want the same state back", goos, st, got)
			}
		}
	}
}

func TestServiceStateHealthy(t *testing.T) {
	t.Parallel()
	cases := map[ServiceState]bool{
		ServiceRunning:      true,
		ServiceStarting:     false,
		ServiceStopped:      false,
		ServiceNotInstalled: false,
		ServiceUnknown:      false,
	}
	for st, want := range cases {
		if got := st.Healthy(); got != want {
			t.Fatalf("%q.Healthy() = %v, want %v", st, got, want)
		}
	}
}
