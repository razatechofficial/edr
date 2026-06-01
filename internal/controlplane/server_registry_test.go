package controlplane

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/razatechofficial/edr/pkg/protocol"
)

func TestHealthAndAgentsWithRegistry(t *testing.T) {
	reg, err := NewRegistry(RegistryConfig{DataDir: t.TempDir(), HeartbeatSec: 30})
	if err != nil {
		t.Fatal(err)
	}
	reg.Register(&protocol.RegistrationRequest{
		AgentId:  "agent-1",
		Hostname: "host-a",
		Os:       "windows",
	})

	srv := NewServerWithRegistry(reg)
	h := srv.Routes()

	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("healthz status = %d", rec.Code)
	}

	req = httptest.NewRequest(http.MethodGet, "/v1/agents", nil)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("agents status = %d", rec.Code)
	}
	if !bytes.Contains(rec.Body.Bytes(), []byte(`"agent_id":"agent-1"`)) {
		t.Fatalf("agents body = %s", rec.Body.String())
	}
}
