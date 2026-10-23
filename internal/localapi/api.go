// Package localapi serves the agent's local control surface: the six routes
// edrctl already calls, plus the world-readable status file the native UI
// reads.
//
// Transport is a Unix domain socket (mode 0660, root:edr) because the
// mutating routes must be able to identify their caller, and only a socket
// carries peer credentials. The 127.0.0.1:9200 HTTP listener is a documented
// fallback for the platforms where no socket can be created; it cannot
// authenticate anyone, so every mutating route is refused on it.
//
// Nothing here reads the agent's config or enrollment state from disk. The
// console user cannot read either of those (0640 config in a 0750 dir, 0600
// enrollment state in a 0700 dir), which is why the UI used to report every
// field negative on a healthy agent. The status file exists to carry exactly
// the fields a read-only view needs, and nothing secret.
package localapi

import (
	"context"
	"time"
)

// Status is the GET /api/v1/status response. The field set and the JSON names
// are those edrctl already decodes (cmd/cli/main.go newStatusCmd,
// cmd/cli/ui.go collectOperatorStatus); do not rename them without changing
// both.
type Status struct {
	Status          string    `json:"status"`
	Version         string    `json:"version"`
	Uptime          string    `json:"uptime"`
	StartedAt       time.Time `json:"started_at"`
	PID             int       `json:"pid"`
	OS              string    `json:"os"`
	Arch            string    `json:"arch"`
	RulesCount      int       `json:"rules_count"`
	CPUPercent      float64   `json:"cpu_percent"`
	MemoryMB        float64   `json:"memory_mb"`
	EventsProcessed uint64    `json:"events_processed"`
	AlertsGenerated uint64    `json:"alerts_generated"`
	Isolated        bool      `json:"isolated"`
}

// ScanRequest is the POST /api/v1/scan body sent by edrctl scan --file.
type ScanRequest struct {
	Path string `json:"path"`
}

// ScanResult is the POST /api/v1/scan response.
type ScanResult struct {
	Path       string   `json:"path"`
	Clean      bool     `json:"clean"`
	Hashes     []string `json:"hashes"`
	YARAHits   []string `json:"yara_hits"`
	IOCMatches []string `json:"ioc_matches"`
	Duration   string   `json:"duration"`
}

// ActionResult is the response shape shared by isolate, release,
// forensics/collect and rules/update.
type ActionResult struct {
	Success bool   `json:"success"`
	Message string `json:"message"`
	Action  string `json:"action"`
}

// Enrollment is the non-secret part of the agent's platform registration.
// IngestHost is a comma-joined host list, matching what edrctl prints.
type Enrollment struct {
	Enrolled   bool
	AgentID    string
	IngestHost string
}

// Controller is the agent behind the API. internal/agent implements it; the
// tests here use fakes, so this package never imports the agent.
type Controller interface {
	// Status reports live runtime counters. It must not block on the network.
	Status(ctx context.Context) Status
	// Enrollment reports the agent id and ingest hosts, with no credentials.
	Enrollment(ctx context.Context) Enrollment
	// Scan evaluates one file against YARA rules and the IOC databases.
	Scan(ctx context.Context, path string) (ScanResult, error)
	// Isolate enforces host network isolation and returns an operator message.
	Isolate(ctx context.Context) (string, error)
	// Release lifts host network isolation.
	Release(ctx context.Context) (string, error)
	// CollectForensics builds a DFIR package from this host.
	CollectForensics(ctx context.Context) (string, error)
	// UpdateRules reloads detection content and returns what was loaded.
	UpdateRules(ctx context.Context) (string, error)
}
