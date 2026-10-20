package localapi

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestWriteStatusFileIsAtomicAndWorldReadable(t *testing.T) {
	t.Parallel()
	dir := filepath.Join(t.TempDir(), "run", "edr-agent")
	path := filepath.Join(dir, "status.json")

	st := PublicStatus{
		Service:    ServiceRunning,
		Enrolled:   true,
		AgentID:    "agent-1",
		IngestHost: "ingest.example:443",
		Version:    "1.2.3",
		Uptime:     "5m0s",
		Detections: 7,
	}
	if err := WriteStatusFile(path, st); err != nil {
		t.Fatalf("WriteStatusFile: %v", err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat status file: %v", err)
	}
	// The console user has to be able to read this, which is the entire
	// reason the file exists.
	if got := info.Mode().Perm(); got != 0o644 {
		t.Fatalf("status file mode = %#o, want 0644", got)
	}
	dirInfo, err := os.Stat(dir)
	if err != nil {
		t.Fatalf("stat status dir: %v", err)
	}
	if got := dirInfo.Mode().Perm(); got != 0o755 {
		t.Fatalf("status dir mode = %#o, want 0755", got)
	}

	// No temporary file is left behind, so no reader can ever open a
	// half-written document.
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read status dir: %v", err)
	}
	for _, e := range entries {
		if e.Name() != "status.json" {
			t.Fatalf("unexpected leftover %q in status dir", e.Name())
		}
	}

	got, availability, err := ReadStatusFile(path, time.Minute)
	if err != nil {
		t.Fatalf("ReadStatusFile: %v", err)
	}
	if availability != StatusOK {
		t.Fatalf("availability = %q, want %q", availability, StatusOK)
	}
	if got.AgentID != "agent-1" || got.Detections != 7 || !got.Enrolled {
		t.Fatalf("round-trip lost fields: %+v", got)
	}
	if got.SchemaVersion != StatusFileSchemaVersion {
		t.Fatalf("schema version = %d, want %d", got.SchemaVersion, StatusFileSchemaVersion)
	}
	if got.UpdatedAt.IsZero() {
		t.Fatal("UpdatedAt must be stamped by the writer")
	}
}

func TestWriteStatusFileReplacesPreviousAtomically(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "status.json")
	for i, version := range []string{"1.0.0", "1.0.1", "1.0.2"} {
		if err := WriteStatusFile(path, PublicStatus{Service: ServiceRunning, Version: version}); err != nil {
			t.Fatalf("write %d: %v", i, err)
		}
		got, availability, err := ReadStatusFile(path, time.Minute)
		if err != nil || availability != StatusOK {
			t.Fatalf("read %d: availability %q err %v", i, availability, err)
		}
		if got.Version != version {
			t.Fatalf("read %d: version = %q, want %q", i, got.Version, version)
		}
	}
}

func TestReadStatusFileAvailability(t *testing.T) {
	t.Parallel()

	fresh, err := json.Marshal(PublicStatus{
		SchemaVersion: StatusFileSchemaVersion,
		Service:       ServiceRunning,
		UpdatedAt:     time.Now().UTC(),
	})
	if err != nil {
		t.Fatalf("marshal fresh: %v", err)
	}
	old, err := json.Marshal(PublicStatus{
		SchemaVersion: StatusFileSchemaVersion,
		Service:       ServiceRunning,
		UpdatedAt:     time.Now().UTC().Add(-time.Hour),
	})
	if err != nil {
		t.Fatalf("marshal stale: %v", err)
	}

	cases := []struct {
		name  string
		body  []byte
		write bool
		want  Availability
	}{
		{"fresh file is ok", fresh, true, StatusOK},
		{"old timestamp is stale", old, true, StatusStale},
		{"absent file is missing", nil, false, StatusMissing},
		// A write cut off by a crash or a full disk leaves a prefix behind.
		{"truncated json is corrupt", fresh[:len(fresh)/2], true, StatusCorrupt},
		{"empty file is corrupt", []byte{}, true, StatusCorrupt},
		{"unrelated json is corrupt", []byte(`{"hello":"world"}`), true, StatusCorrupt},
		{"wrong schema version is corrupt", []byte(`{"schema_version":99,"updated_at":"2026-01-01T00:00:00Z"}`), true, StatusCorrupt},
		{"valid json without timestamp is corrupt", []byte(`{"schema_version":1}`), true, StatusCorrupt},
		{"garbage is corrupt", []byte("\x00\x01not json at all"), true, StatusCorrupt},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			path := filepath.Join(t.TempDir(), "status.json")
			if tc.write {
				if err := os.WriteFile(path, tc.body, 0o644); err != nil {
					t.Fatalf("seed status file: %v", err)
				}
			}
			_, availability, err := ReadStatusFile(path, time.Minute)
			if availability != tc.want {
				t.Fatalf("availability = %q (err %v), want %q", availability, err, tc.want)
			}
			if tc.want != StatusOK && tc.want != StatusStale && err == nil {
				t.Fatalf("availability %q must come with an error", availability)
			}
		})
	}
}

func TestReadStatusFileUnreadable(t *testing.T) {
	t.Parallel()
	if os.Geteuid() == 0 {
		t.Skip("root can read a 0000 file, so unreadable cannot be provoked")
	}
	path := filepath.Join(t.TempDir(), "status.json")
	if err := os.WriteFile(path, []byte(`{"schema_version":1}`), 0o000); err != nil {
		t.Fatalf("seed status file: %v", err)
	}
	_, availability, err := ReadStatusFile(path, time.Minute)
	if availability != StatusUnreadable {
		t.Fatalf("availability = %q (err %v), want %q", availability, err, StatusUnreadable)
	}
}

// TestPublicStatusCarriesNoSecrets guards the one invariant that matters for a
// world-readable file: nothing in it may be a credential. It checks both the
// field set and the encoded JSON, so neither a renamed field nor an embedded
// struct can smuggle one in.
func TestPublicStatusCarriesNoSecrets(t *testing.T) {
	t.Parallel()

	allowed := map[string]struct{}{
		"schema_version": {},
		"service":        {},
		"enrolled":       {},
		"agent_id":       {},
		"ingest_host":    {},
		"version":        {},
		"uptime":         {},
		"detections":     {},
		"isolated":       {},
		"updated_at":     {},
	}
	banned := []string{
		"token", "secret", "password", "passwd", "credential", "key",
		"cert", "pem", "private", "bearer", "signature", "seed", "salt",
	}

	typ := reflect.TypeOf(PublicStatus{})
	for i := 0; i < typ.NumField(); i++ {
		tag := typ.Field(i).Tag.Get("json")
		name := strings.Split(tag, ",")[0]
		if name == "" {
			t.Fatalf("field %s has no json name; an unnamed field is not reviewable", typ.Field(i).Name)
		}
		if _, ok := allowed[name]; !ok {
			t.Fatalf("field %q is not in the reviewed field set for a world-readable file", name)
		}
	}

	// Fill every field so nothing is dropped by omitempty, then inspect the
	// encoded document.
	path := filepath.Join(t.TempDir(), "status.json")
	if err := WriteStatusFile(path, PublicStatus{
		Service:    ServiceRunning,
		Enrolled:   true,
		AgentID:    "agent-1",
		IngestHost: "ingest.example:443",
		Version:    "1.2.3",
		Uptime:     "1h0m0s",
		Detections: 3,
		Isolated:   true,
	}); err != nil {
		t.Fatalf("WriteStatusFile: %v", err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read status file: %v", err)
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("parse status file: %v", err)
	}
	for key := range doc {
		if _, ok := allowed[key]; !ok {
			t.Fatalf("status file carries unreviewed key %q", key)
		}
		for _, bad := range banned {
			if strings.Contains(strings.ToLower(key), bad) {
				t.Fatalf("status file key %q looks like a secret (%q)", key, bad)
			}
		}
	}
}

// TestPublicFromCopiesOnlyNonSecretFields pins what PublicFrom is allowed to
// take from the live status and the enrollment.
func TestPublicFromCopiesOnlyNonSecretFields(t *testing.T) {
	t.Parallel()
	st := Status{Version: "2.0.0", Uptime: "9m0s", AlertsGenerated: 11, Isolated: true}
	en := Enrollment{Enrolled: true, AgentID: "agent-9", IngestHost: "a:443,b:443"}

	got := PublicFrom(st, en, ServiceRunning)
	want := PublicStatus{
		SchemaVersion: StatusFileSchemaVersion,
		Service:       ServiceRunning,
		Enrolled:      true,
		AgentID:       "agent-9",
		IngestHost:    "a:443,b:443",
		Version:       "2.0.0",
		Uptime:        "9m0s",
		Detections:    11,
		Isolated:      true,
		UpdatedAt:     got.UpdatedAt,
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("PublicFrom() = %+v, want %+v", got, want)
	}
	if got.UpdatedAt.IsZero() {
		t.Fatal("PublicFrom must stamp UpdatedAt")
	}
}

func TestStatusFilePath(t *testing.T) {
	t.Parallel()
	cases := []struct {
		goos        string
		programData string
		want        string
	}{
		{"linux", "", "/run/edr-agent/status.json"},
		{"darwin", "", "/var/run/edr-agent/status.json"},
		{"windows", `D:\Data`, filepath.Join(`D:\Data`, "EDR Agent", "status.json")},
		{"windows", "", filepath.Join(`C:\ProgramData`, "EDR Agent", "status.json")},
	}
	for _, tc := range cases {
		t.Run(tc.goos+tc.programData, func(t *testing.T) {
			t.Parallel()
			if got := statusFilePath(tc.goos, tc.programData); got != tc.want {
				t.Fatalf("statusFilePath(%q, %q) = %q, want %q", tc.goos, tc.programData, got, tc.want)
			}
		})
	}
}

func TestWriteStatusFileRejectsEmptyPath(t *testing.T) {
	t.Parallel()
	if err := WriteStatusFile("", PublicStatus{}); err == nil {
		t.Fatal("WriteStatusFile(\"\") must fail")
	}
	if _, availability, err := ReadStatusFile("", 0); err == nil || availability != StatusMissing {
		t.Fatalf("ReadStatusFile(\"\") = %q, %v; want missing and an error", availability, err)
	}
}
