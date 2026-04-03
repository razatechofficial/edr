package controlplane

import (
	"encoding/json"
	"net/http"
	"sync"
	"time"
)

type Server struct {
	mu          sync.RWMutex
	enrolledAt  map[string]time.Time
	lastBeatAt  map[string]time.Time
	latestRules map[string]string
}

func NewServer() *Server {
	return &Server{
		enrolledAt:  map[string]time.Time{},
		lastBeatAt:  map[string]time.Time{},
		latestRules: map[string]string{},
	}
}

func (s *Server) Routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/enroll", s.handleEnroll)
	mux.HandleFunc("/v1/heartbeat", s.handleHeartbeat)
	mux.HandleFunc("/v1/ingest", s.handleIngest)
	mux.HandleFunc("/v1/rules/evaluate", s.handleRuleEvaluate)
	return mux
}

type enrollRequest struct {
	EndpointID string `json:"endpoint_id"`
}

func (s *Server) handleEnroll(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req enrollRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.EndpointID == "" {
		http.Error(w, "invalid payload", http.StatusBadRequest)
		return
	}

	now := time.Now().UTC()
	s.mu.Lock()
	s.enrolledAt[req.EndpointID] = now
	s.lastBeatAt[req.EndpointID] = now
	s.mu.Unlock()

	_ = json.NewEncoder(w).Encode(map[string]any{
		"status":      "ok",
		"endpoint_id": req.EndpointID,
		"enrolled_at": now,
	})
}

func (s *Server) handleHeartbeat(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req enrollRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.EndpointID == "" {
		http.Error(w, "invalid payload", http.StatusBadRequest)
		return
	}
	now := time.Now().UTC()
	s.mu.Lock()
	s.lastBeatAt[req.EndpointID] = now
	s.mu.Unlock()
	_ = json.NewEncoder(w).Encode(map[string]any{"status": "ok", "last_seen": now})
}

func (s *Server) handleIngest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	_ = json.NewEncoder(w).Encode(map[string]any{"status": "accepted"})
}

func (s *Server) handleRuleEvaluate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	_ = json.NewEncoder(w).Encode(map[string]any{
		"matched": false,
		"reason":  "stub evaluator; wired in detect milestone",
	})
}
