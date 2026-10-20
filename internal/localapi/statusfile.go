package localapi

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"time"
)

// StatusFileSchemaVersion is bumped when a field in PublicStatus changes
// meaning, so an old reader can refuse a file it does not understand.
const StatusFileSchemaVersion = 1

// DefaultStatusMaxAge is how long a status file is trusted after its
// UpdatedAt. It is several status intervals, so one slow write does not make
// a running agent look dead.
const DefaultStatusMaxAge = 90 * time.Second

// DefaultStatusInterval is how often the agent rewrites the status file when
// nothing has changed.
const DefaultStatusInterval = 15 * time.Second

// PublicStatus is the world-readable view of the agent, written atomically at
// mode 0644 in a world-traversable directory. It holds exactly what a
// read-only UI needs and nothing else.
//
// Every reader is unprivileged by definition, so this file must never carry a
// secret: no enrollment or bootstrap token, no private key or certificate
// material, no API credentials, no config dump. TestPublicStatusCarriesNoSecrets
// enforces that on the field set; keep it that way when adding a field.
type PublicStatus struct {
	SchemaVersion int          `json:"schema_version"`
	Service       ServiceState `json:"service"`
	Enrolled      bool         `json:"enrolled"`
	AgentID       string       `json:"agent_id"`
	IngestHost    string       `json:"ingest_host"`
	Version       string       `json:"version"`
	Uptime        string       `json:"uptime"`
	Detections    uint64       `json:"detections"`
	Isolated      bool         `json:"isolated"`
	UpdatedAt     time.Time    `json:"updated_at"`
}

// Availability says how far a reader should trust a status file. The UI shows
// each of these as its own state: a missing or stale file means the agent is
// not reporting, which is not the same thing as an agent that reports it is
// not enrolled.
type Availability string

const (
	// StatusOK means the file was read and is within maxAge.
	StatusOK Availability = "ok"
	// StatusStale means the file parsed but its UpdatedAt is too old, so the
	// agent stopped without clearing it.
	StatusStale Availability = "stale"
	// StatusMissing means no status file exists: the agent has not run since
	// the runtime directory was created.
	StatusMissing Availability = "missing"
	// StatusUnreadable means the file exists but could not be opened.
	StatusUnreadable Availability = "unreadable"
	// StatusCorrupt means the file exists but is not a status document, which
	// is what a truncated write or a schema change looks like.
	StatusCorrupt Availability = "corrupt"
)

// PublicFrom projects the live status, the enrollment and a service state
// into the public view. service is normally ServiceRunning, because only a
// running agent writes the file.
func PublicFrom(st Status, en Enrollment, service ServiceState) PublicStatus {
	return PublicStatus{
		SchemaVersion: StatusFileSchemaVersion,
		Service:       service,
		Enrolled:      en.Enrolled,
		AgentID:       en.AgentID,
		IngestHost:    en.IngestHost,
		Version:       st.Version,
		Uptime:        st.Uptime,
		Detections:    st.AlertsGenerated,
		Isolated:      st.Isolated,
		UpdatedAt:     time.Now().UTC(),
	}
}

// WriteStatusFile writes st to path atomically: a temporary file in the same
// directory, then a rename. A reader therefore sees either the previous
// document or the new one, never a half-written one.
func WriteStatusFile(path string, st PublicStatus) error {
	if path == "" {
		return errors.New("localapi: empty status file path")
	}
	if st.SchemaVersion == 0 {
		st.SchemaVersion = StatusFileSchemaVersion
	}
	if st.UpdatedAt.IsZero() {
		st.UpdatedAt = time.Now().UTC()
	}
	dir := filepath.Dir(path)
	// 0755: the console user has to traverse this directory to read the file.
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("localapi: create status dir %s: %w", dir, err)
	}
	body, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return fmt.Errorf("localapi: encode status: %w", err)
	}
	body = append(body, '\n')

	tmp, err := os.CreateTemp(dir, filepath.Base(path)+".tmp")
	if err != nil {
		return fmt.Errorf("localapi: create temp status file: %w", err)
	}
	tmpName := tmp.Name()
	defer func() {
		// Only reached on a failure path; a successful rename removes it.
		if _, statErr := os.Stat(tmpName); statErr == nil {
			_ = os.Remove(tmpName)
		}
	}()
	if _, err := tmp.Write(body); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("localapi: write status file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("localapi: close status file: %w", err)
	}
	// CreateTemp makes the file 0600, and WriteFile-style modes are cut by
	// the agent's umask, so set the mode explicitly: the point of this file
	// is that an unprivileged UI can read it.
	if err := os.Chmod(tmpName, 0o644); err != nil {
		return fmt.Errorf("localapi: chmod status file: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("localapi: publish status file: %w", err)
	}
	return nil
}

// ReadStatusFile reads the status file and reports how far it can be trusted.
// A zero maxAge uses DefaultStatusMaxAge. The returned PublicStatus is
// meaningful for StatusOK and StatusStale, and zero otherwise.
func ReadStatusFile(path string, maxAge time.Duration) (PublicStatus, Availability, error) {
	if maxAge <= 0 {
		maxAge = DefaultStatusMaxAge
	}
	if path == "" {
		return PublicStatus{}, StatusMissing, errors.New("localapi: empty status file path")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return PublicStatus{}, StatusMissing, err
		}
		return PublicStatus{}, StatusUnreadable, err
	}
	var st PublicStatus
	if err := json.Unmarshal(raw, &st); err != nil {
		return PublicStatus{}, StatusCorrupt, fmt.Errorf("localapi: parse status file %s: %w", path, err)
	}
	// A document with no schema version or no timestamp is not a status file,
	// however well it parses: that is what a truncated write looks like once
	// the JSON happens to stay valid.
	if st.SchemaVersion != StatusFileSchemaVersion || st.UpdatedAt.IsZero() {
		return PublicStatus{}, StatusCorrupt, fmt.Errorf(
			"localapi: status file %s has schema version %d, want %d",
			path, st.SchemaVersion, StatusFileSchemaVersion)
	}
	if time.Since(st.UpdatedAt) > maxAge {
		return st, StatusStale, nil
	}
	return st, StatusOK, nil
}

// DefaultStatusFile returns the status file path for this platform.
func DefaultStatusFile() string {
	return statusFilePath(runtime.GOOS, os.Getenv("ProgramData"))
}

// statusFilePath picks a directory the agent owns and every local user can
// traverse. The agent data dirs are deliberately not world-traversable, so
// the status file cannot live in them.
func statusFilePath(goos, programData string) string {
	switch goos {
	case "linux":
		return "/run/edr-agent/status.json"
	case "darwin":
		return "/var/run/edr-agent/status.json"
	case "windows":
		if programData == "" {
			programData = `C:\ProgramData`
		}
		return filepath.Join(programData, "EDR Agent", "status.json")
	default:
		return filepath.Join(os.TempDir(), "edr-agent", "status.json")
	}
}
