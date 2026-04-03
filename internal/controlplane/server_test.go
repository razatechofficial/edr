package controlplane

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestEnrollAndHeartbeat(t *testing.T) {
	srv := NewServer()
	h := srv.Routes()

	req := httptest.NewRequest(http.MethodPost, "/v1/enroll", bytes.NewBufferString(`{"endpoint_id":"ep-1"}`))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("enroll status = %d", rec.Code)
	}

	req = httptest.NewRequest(http.MethodPost, "/v1/heartbeat", bytes.NewBufferString(`{"endpoint_id":"ep-1"}`))
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("heartbeat status = %d", rec.Code)
	}
}
