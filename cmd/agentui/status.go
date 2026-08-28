package main

import (
	"encoding/json"
	"os/exec"
	"strings"
	"time"
)

type operatorHostProbe struct {
	Host   string `json:"host"`
	OK     bool   `json:"ok"`
	Detail string `json:"detail,omitempty"`
}

type operatorStatus struct {
	Config           string              `json:"config"`
	Service          string              `json:"service"`
	Enrolled         bool                `json:"enrolled"`
	AgentID          string              `json:"agent_id,omitempty"`
	MachineID        string              `json:"machine_id,omitempty"`
	Ingest           string              `json:"ingest,omitempty"`
	Runtime          string              `json:"runtime,omitempty"`
	Version          string              `json:"version,omitempty"`
	Uptime           string              `json:"uptime,omitempty"`
	Detections       uint64              `json:"detections"`
	EventsProc       uint64              `json:"events_processed,omitempty"`
	Blocks           uint64              `json:"blocks,omitempty"`
	RulesCount       int                 `json:"rules_count,omitempty"`
	SpoolBytes       int64               `json:"spool_bytes,omitempty"`
	CertExpiry       string              `json:"cert_not_after,omitempty"`
	CPUPercent       float64             `json:"cpu_percent,omitempty"`
	MemoryMB         float64             `json:"memory_mb,omitempty"`
	Isolated         bool                `json:"isolated"`
	ControlAPI       string              `json:"control_api"`
	IngestConfigured bool                `json:"ingest_configured"`
	IngestEnv        bool                `json:"ingest_env"`
	IngestOK         bool                `json:"ingest_ok"`
	IngestFault      string              `json:"ingest_fault,omitempty"`
	Hosts            []operatorHostProbe `json:"hosts,omitempty"`
	UpdatedAt        string              `json:"updated_at"`
	Error            string              `json:"error,omitempty"`
}

func loadStatus() operatorStatus {
	out, err := runEdrctl("ui", "--json")
	if err != nil {
		st := parseLegacyStatus(out)
		if st.Service == "" {
			st.Service = "unknown"
		}
		if out == "" {
			st.Error = friendlyExecError(err)
		} else {
			st.Error = strings.TrimSpace(out + "\n" + err.Error())
		}
		st.UpdatedAt = time.Now().Format(time.RFC3339)
		enrichStatus(&st)
		return st
	}
	var st operatorStatus
	if json.Unmarshal([]byte(out), &st) != nil {
		st = parseLegacyStatus(out)
		enrichStatus(&st)
		return st
	}
	enrichStatus(&st)
	return st
}

func parseLegacyStatus(raw string) operatorStatus {
	st := operatorStatus{UpdatedAt: time.Now().Format(time.RFC3339)}
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(line, "Service:"):
			st.Service = strings.TrimSpace(strings.TrimPrefix(line, "Service:"))
		case strings.HasPrefix(line, "Enrollment:"):
			v := strings.ToLower(strings.TrimSpace(strings.TrimPrefix(line, "Enrollment:")))
			st.Enrolled = strings.Contains(v, "enrolled") && !strings.Contains(v, "not")
		case strings.HasPrefix(line, "Agent ID:"):
			st.AgentID = strings.TrimSpace(strings.TrimPrefix(line, "Agent ID:"))
		case strings.HasPrefix(line, "Ingest:"):
			st.Ingest = strings.TrimSpace(strings.TrimPrefix(line, "Ingest:"))
		case strings.HasPrefix(line, "Runtime:"):
			st.Runtime = strings.TrimSpace(strings.TrimPrefix(line, "Runtime:"))
		case strings.HasPrefix(line, "Uptime:"):
			st.Uptime = strings.TrimSpace(strings.TrimPrefix(line, "Uptime:"))
		}
	}
	return st
}

func friendlyExecError(err error) string {
	msg := err.Error()
	if strings.Contains(msg, "Bad CPU type") || strings.Contains(msg, "exec format error") {
		return "This installer does not match this Mac. On Apple Silicon download the arm64 package; on Intel download amd64."
	}
	if ee, ok := err.(*exec.Error); ok && ee.Err == exec.ErrNotFound {
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

func clipErr(s string) string {
	s = strings.TrimSpace(s)
	if len(s) > 400 {
		return s[:400] + "…"
	}
	return s
}

func serviceHealthy(s string) bool {
	v := strings.ToLower(strings.TrimSpace(s))
	switch v {
	case "running", "started", "active", "activating", "starting", "start_pending":
		return true
	default:
		return false
	}
}
