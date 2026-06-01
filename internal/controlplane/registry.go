package controlplane

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/razatechofficial/edr/pkg/protocol"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// AgentRecord tracks a registered endpoint.
type AgentRecord struct {
	AgentID       string            `json:"agent_id"`
	Hostname      string            `json:"hostname"`
	OS            string            `json:"os"`
	Arch          string            `json:"arch"`
	Version       string            `json:"version"`
	Commit        string            `json:"commit,omitempty"`
	Capabilities  []string          `json:"capabilities,omitempty"`
	Labels        map[string]string `json:"labels,omitempty"`
	RegisteredAt  time.Time         `json:"registered_at"`
	LastHeartbeat time.Time         `json:"last_heartbeat"`
	LastStatus    string            `json:"last_status,omitempty"`
	EventsTotal   uint64            `json:"events_processed,omitempty"`
	AlertsTotal   uint64            `json:"alerts_generated,omitempty"`
	RulesLoaded   int32             `json:"rules_loaded,omitempty"`
	PolicyHash    string            `json:"policy_hash,omitempty"`
}

// Registry stores enrolled agents and appends alerts to disk.
type Registry struct {
	mu          sync.RWMutex
	agents      map[string]*AgentRecord
	alertsPath  string
	agentsPath  string
	heartbeatSec int32
}

// RegistryConfig configures on-disk fleet state.
type RegistryConfig struct {
	DataDir      string
	HeartbeatSec int32
}

// NewRegistry creates a registry backed by JSON state files under dataDir.
func NewRegistry(cfg RegistryConfig) (*Registry, error) {
	if cfg.DataDir == "" {
		cfg.DataDir = "."
	}
	if err := os.MkdirAll(cfg.DataDir, 0o750); err != nil {
		return nil, err
	}
	if cfg.HeartbeatSec <= 0 {
		cfg.HeartbeatSec = 30
	}
	r := &Registry{
		agents:       map[string]*AgentRecord{},
		alertsPath:   filepath.Join(cfg.DataDir, "alerts.jsonl"),
		agentsPath:   filepath.Join(cfg.DataDir, "agents.json"),
		heartbeatSec: cfg.HeartbeatSec,
	}
	if err := r.loadAgents(); err != nil {
		return nil, err
	}
	return r, nil
}

func (r *Registry) DefaultHeartbeatSec() int32 {
	return r.heartbeatSec
}

func (r *Registry) Register(req *protocol.RegistrationRequest) *protocol.RegistrationResponse {
	now := time.Now().UTC()
	id := req.GetAgentId()
	if id == "" {
		return &protocol.RegistrationResponse{
			Accepted: false,
			Message:  "agent_id required",
		}
	}

	rec := &AgentRecord{
		AgentID:       id,
		Hostname:      req.GetHostname(),
		OS:            req.GetOs(),
		Arch:          req.GetArch(),
		Version:       req.GetVersion(),
		Commit:        req.GetCommit(),
		Capabilities:  append([]string(nil), req.GetCapabilities()...),
		Labels:        cloneLabels(req.GetLabels()),
		RegisteredAt:  now,
		LastHeartbeat: now,
		LastStatus:    "registered",
	}

	r.mu.Lock()
	if existing, ok := r.agents[id]; ok {
		rec.RegisteredAt = existing.RegisteredAt
	}
	r.agents[id] = rec
	_ = r.persistAgentsLocked()
	r.mu.Unlock()

	return &protocol.RegistrationResponse{
		Accepted:     true,
		AgentId:      id,
		Message:      "registered",
		HeartbeatSec: r.heartbeatSec,
	}
}

func (r *Registry) Heartbeat(req *protocol.HeartbeatRequest) *protocol.HeartbeatResponse {
	id := req.GetAgentId()
	now := time.Now().UTC()

	r.mu.Lock()
	rec, ok := r.agents[id]
	if !ok {
		rec = &AgentRecord{
			AgentID:      id,
			RegisteredAt: now,
		}
		r.agents[id] = rec
	}
	rec.LastHeartbeat = now
	rec.LastStatus = req.GetStatus()
	rec.EventsTotal = req.GetEventsProcessed()
	rec.AlertsTotal = req.GetAlertsGenerated()
	rec.RulesLoaded = req.GetRulesLoaded()
	if req.GetPolicyHash() != "" {
		rec.PolicyHash = req.GetPolicyHash()
	}
	if req.GetVersion() != "" {
		rec.Version = req.GetVersion()
	}
	_ = r.persistAgentsLocked()
	r.mu.Unlock()

	return &protocol.HeartbeatResponse{
		Accepted:         true,
		NextHeartbeatSec: r.heartbeatSec,
	}
}

func (r *Registry) RecordAlert(alert *protocol.Alert) error {
	if alert == nil {
		return nil
	}
	entry := map[string]any{
		"received_at": time.Now().UTC(),
		"alert_id":    alert.GetAlertId(),
		"agent_id":    alert.GetEndpointId(),
		"rule_id":     alert.GetRuleId(),
		"severity":    alert.GetSeverity().String(),
		"title":       alert.GetTitle(),
		"description": alert.GetDescription(),
		"timestamp":   timestampString(alert.GetTimestamp()),
		"process": map[string]any{
			"pid":  alert.GetProcessPid(),
			"name": alert.GetProcessName(),
			"path": alert.GetProcessPath(),
		},
	}
	if len(alert.GetOcsf()) > 0 {
		entry["ocsf_json"] = json.RawMessage(alert.GetOcsf())
	}
	line, err := json.Marshal(entry)
	if err != nil {
		return err
	}
	f, err := os.OpenFile(r.alertsPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o640)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = f.Write(append(line, '\n'))
	return err
}

func (r *Registry) AgentCount() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.agents)
}

// ListAgents returns a snapshot of enrolled agents (newest heartbeat first).
func (r *Registry) ListAgents() []AgentRecord {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]AgentRecord, 0, len(r.agents))
	for _, rec := range r.agents {
		out = append(out, *rec)
	}
	for i := 0; i < len(out); i++ {
		for j := i + 1; j < len(out); j++ {
			if out[j].LastHeartbeat.After(out[i].LastHeartbeat) {
				out[i], out[j] = out[j], out[i]
			}
		}
	}
	return out
}

func (r *Registry) loadAgents() error {
	data, err := os.ReadFile(r.agentsPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	var records []AgentRecord
	if err := json.Unmarshal(data, &records); err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	for i := range records {
		rec := records[i]
		r.agents[rec.AgentID] = &rec
	}
	return nil
}

func (r *Registry) persistAgentsLocked() error {
	records := make([]*AgentRecord, 0, len(r.agents))
	for _, rec := range r.agents {
		records = append(records, rec)
	}
	data, err := json.MarshalIndent(records, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	tmp := r.agentsPath + ".tmp"
	if err := os.WriteFile(tmp, data, 0o640); err != nil {
		return err
	}
	return os.Rename(tmp, r.agentsPath)
}

func cloneLabels(in map[string]string) map[string]string {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

func timestampString(ts *timestamppb.Timestamp) string {
	if ts == nil {
		return ""
	}
	return ts.AsTime().UTC().Format(time.RFC3339Nano)
}
