package response

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"go.uber.org/zap"

	"github.com/razatechofficial/edr/internal/detection"
)

// An unconfigured deployment must not sanction destructive actions. A playbook
// declaring approval_required is asking a human to authorise killing a process
// or isolating a host; answering that automatically because nothing was set up
// defeats the declaration.
func TestAnUnconfiguredApprovalModeDeniesRatherThanApproves(t *testing.T) {
	for _, mode := range []string{"", "   ", "nonsense", "AUTO-ish"} {
		gw := buildApprovalGateway(ApprovalConfig{Mode: mode}, zap.NewNop())
		ok, err := gw.RequestApproval(context.Background(), detection.Detection{}, PlaybookYAML{ID: "PB-001"})
		if err != nil {
			t.Fatalf("mode %q: %v", mode, err)
		}
		if ok {
			t.Errorf("mode %q approved a playbook with no approval mode configured", mode)
		}
	}
}

// Auto-approval remains available, but only when asked for by name.
func TestAutoApprovalIsStillAvailableWhenChosenDeliberately(t *testing.T) {
	gw := buildApprovalGateway(ApprovalConfig{Mode: "auto"}, zap.NewNop())
	ok, err := gw.RequestApproval(context.Background(), detection.Detection{}, PlaybookYAML{ID: "PB-001"})
	if err != nil || !ok {
		t.Fatalf("explicit auto mode did not approve: ok=%v err=%v", ok, err)
	}
}

func TestTheCallbackServerRefusesToStartWithoutAToken(t *testing.T) {
	// An approval endpoint with no credential is worse than no endpoint: it
	// needs only reachability and a guessable id.
	s := &standardLayer{logger: zap.NewNop(), callbackAddr: "127.0.0.1:0"}
	s.startApprovalCallback()
	if s.callbackSrv != nil {
		t.Fatal("the callback server started with no token configured")
	}
}

// buildCallbackMux is the handler under test, exercised through httptest so the
// token and method checks are covered without binding a port.
func approvalHandler(t *testing.T, token string) http.Handler {
	t.Helper()
	s := &standardLayer{logger: zap.NewNop(), callbackAddr: "127.0.0.1:0", callbackToken: token}
	s.startApprovalCallback()
	if s.callbackSrv == nil {
		t.Fatal("callback server did not start")
	}
	t.Cleanup(func() { _ = s.callbackSrv.Close() })
	return s.callbackSrv.Handler
}

func TestApprovalRequiresTheTokenAndPost(t *testing.T) {
	h := approvalHandler(t, "s3cret-token-value")

	// GET is refused: it is reachable from a browser the operator merely
	// visits, and is prefetched and retried by things that should not approve.
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/approve/abc", nil))
	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("GET returned %d, want 405", rec.Code)
	}

	// POST without the token is unauthorised.
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/approve/abc", nil))
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("POST with no token returned %d, want 401", rec.Code)
	}

	// A wrong token is unauthorised.
	req := httptest.NewRequest(http.MethodPost, "/approve/abc", nil)
	req.Header.Set("X-EDR-Approval-Token", "wrong")
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("POST with a wrong token returned %d, want 401", rec.Code)
	}

	// The right token is accepted.
	req = httptest.NewRequest(http.MethodPost, "/approve/abc", nil)
	req.Header.Set("X-EDR-Approval-Token", "s3cret-token-value")
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("POST with the right token returned %d, want 200", rec.Code)
	}
}

func TestRejectIsGuardedTheSameWayAsApprove(t *testing.T) {
	// A forged rejection is a denial of service on the response pipeline.
	h := approvalHandler(t, "s3cret-token-value")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/reject/abc", nil))
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("unauthenticated reject returned %d, want 401", rec.Code)
	}
}
