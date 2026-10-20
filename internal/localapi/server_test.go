package localapi

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// fakeController is a Controller that records what the API asked it to do.
type fakeController struct {
	status     Status
	enrollment Enrollment
	scan       ScanResult
	scanErr    error
	actionErr  error

	isolates atomic.Int32
	releases atomic.Int32
	collects atomic.Int32
	reloads  atomic.Int32
	scans    atomic.Int32
}

func (f *fakeController) Status(context.Context) Status         { return f.status }
func (f *fakeController) Enrollment(context.Context) Enrollment { return f.enrollment }
func (f *fakeController) Isolate(context.Context) (string, error) {
	f.isolates.Add(1)
	return "host network isolated", f.actionErr
}
func (f *fakeController) Release(context.Context) (string, error) {
	f.releases.Add(1)
	return "host network released", f.actionErr
}
func (f *fakeController) CollectForensics(context.Context) (string, error) {
	f.collects.Add(1)
	return "dfir package written", f.actionErr
}
func (f *fakeController) UpdateRules(context.Context) (string, error) {
	f.reloads.Add(1)
	return "reloaded detection rules from disk", f.actionErr
}
func (f *fakeController) Scan(_ context.Context, path string) (ScanResult, error) {
	f.scans.Add(1)
	res := f.scan
	res.Path = path
	return res, f.scanErr
}

// shortTempDir returns a directory short enough to hold a Unix domain socket.
// The sun_path limit is about a hundred bytes and the default temp root on
// macOS alone can exceed it.
func shortTempDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if len(filepath.Join(dir, "control.sock")) < 100 {
		return dir
	}
	short, err := os.MkdirTemp("/tmp", "edrlocalapi")
	if err != nil {
		t.Skipf("no short directory available for a unix socket: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(short) })
	return short
}

func newTestServer(t *testing.T, ctrl Controller, cfg Config) (*Server, *http.Client) {
	t.Helper()
	dir := shortTempDir(t)
	if cfg.SocketPath == "" {
		cfg.SocketPath = filepath.Join(dir, "control.sock")
	}
	if cfg.StatusFile == "" {
		cfg.StatusFile = filepath.Join(dir, "status.json")
	}
	if cfg.HTTPAddr == "" {
		cfg.HTTPAddr = "127.0.0.1:0"
	}
	if cfg.StatusInterval == 0 {
		cfg.StatusInterval = time.Hour
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}

	srv, err := New(ctrl, cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	if err := srv.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(func() { _ = srv.Close() })

	client := &http.Client{Timeout: 5 * time.Second}
	switch srv.Transport() {
	case transportSocket:
		socket := cfg.SocketPath
		client.Transport = &http.Transport{
			DialContext: func(_ context.Context, _, _ string) (net.Conn, error) {
				return net.DialTimeout("unix", socket, 2*time.Second)
			},
		}
	default:
		addr := srv.Addr().String()
		client.Transport = &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, "tcp", addr)
			},
		}
	}
	return srv, client
}

func TestStatusRouteIsUnprivileged(t *testing.T) {
	ctrl := &fakeController{
		status: Status{Status: "running", Version: "1.2.3", Uptime: "4m0s", RulesCount: 12, AlertsGenerated: 3},
	}
	_, client := newTestServer(t, ctrl, Config{})

	resp, err := client.Get("http://localhost/api/v1/status")
	if err != nil {
		t.Fatalf("GET /api/v1/status: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	// The shape must be the one edrctl already decodes.
	var got struct {
		Status     string `json:"status"`
		Version    string `json:"version"`
		Uptime     string `json:"uptime"`
		RulesCount int    `json:"rules_count"`
		AlertsGen  uint64 `json:"alerts_generated"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got.Status != "running" || got.Version != "1.2.3" || got.Uptime != "4m0s" ||
		got.RulesCount != 12 || got.AlertsGen != 3 {
		t.Fatalf("status payload = %+v", got)
	}
}

// TestMutatingRoutesRequireRoot is the peer-credential check end to end over a
// real socket: the caller is this test process, and the server must allow or
// refuse it on the kernel's word about its uid, not on anything in the
// request.
func TestMutatingRoutesRequireRoot(t *testing.T) {
	ctrl := &fakeController{}
	_, client := newTestServer(t, ctrl, Config{})

	privileged := os.Geteuid() == 0
	routes := []struct {
		path string
		body string
		ran  func() int32
	}{
		{path: "/api/v1/isolate", ran: func() int32 { return ctrl.isolates.Load() }},
		{path: "/api/v1/release", ran: func() int32 { return ctrl.releases.Load() }},
		{path: "/api/v1/forensics/collect", ran: func() int32 { return ctrl.collects.Load() }},
		{path: "/api/v1/rules/update", ran: func() int32 { return ctrl.reloads.Load() }},
		{path: "/api/v1/scan", body: `{"path":"/bin/sh"}`, ran: func() int32 { return ctrl.scans.Load() }},
	}

	for _, route := range routes {
		t.Run(route.path, func(t *testing.T) {
			var body io.Reader
			if route.body != "" {
				body = strings.NewReader(route.body)
			}
			req, err := http.NewRequest(http.MethodPost, "http://localhost"+route.path, body)
			if err != nil {
				t.Fatalf("new request: %v", err)
			}
			req.Header.Set("Content-Type", "application/json")
			resp, err := client.Do(req)
			if err != nil {
				t.Fatalf("POST %s: %v", route.path, err)
			}
			defer resp.Body.Close()
			payload, _ := io.ReadAll(resp.Body)

			if privileged {
				if resp.StatusCode != http.StatusOK {
					t.Fatalf("POST %s as root = %d (%s), want 200", route.path, resp.StatusCode, payload)
				}
				if route.ran() == 0 {
					t.Fatalf("POST %s as root did not reach the controller", route.path)
				}
				return
			}
			if resp.StatusCode != http.StatusForbidden {
				t.Fatalf("POST %s as uid %d = %d (%s), want 403",
					route.path, os.Geteuid(), resp.StatusCode, payload)
			}
			if !strings.Contains(string(payload), "not privileged") {
				t.Fatalf("POST %s refusal did not say why: %s", route.path, payload)
			}
			// The refusal has to happen before the action does.
			if route.ran() != 0 {
				t.Fatalf("POST %s reached the controller despite being refused", route.path)
			}
		})
	}
}

func TestStatusStaysReadableWhenMutatingIsRefused(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("the test process is root, so nothing is refused")
	}
	ctrl := &fakeController{status: Status{Status: "running"}}
	_, client := newTestServer(t, ctrl, Config{})

	resp, err := client.Post("http://localhost/api/v1/isolate", "application/json", nil)
	if err != nil {
		t.Fatalf("POST isolate: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("isolate = %d, want 403", resp.StatusCode)
	}

	statusResp, err := client.Get("http://localhost/api/v1/status")
	if err != nil {
		t.Fatalf("GET status: %v", err)
	}
	_ = statusResp.Body.Close()
	if statusResp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200 for an unprivileged caller", statusResp.StatusCode)
	}
}

// TestHTTPFallbackRefusesMutatingRoutes pins the documented behaviour of the
// loopback fallback: a TCP connection cannot name its caller, so nothing that
// changes the host runs over it.
func TestHTTPFallbackRefusesMutatingRoutes(t *testing.T) {
	dir := shortTempDir(t)
	// A regular file where the socket's parent directory should be, so the
	// socket cannot be created even for root.
	blocker := filepath.Join(dir, "blocked")
	if err := os.WriteFile(blocker, []byte("not a directory\n"), 0o600); err != nil {
		t.Fatalf("seed blocker: %v", err)
	}

	ctrl := &fakeController{status: Status{Status: "running"}}
	srv, client := newTestServer(t, ctrl, Config{
		SocketPath: filepath.Join(blocker, "control.sock"),
		StatusFile: filepath.Join(dir, "status.json"),
	})
	if srv.Transport() != transportHTTP {
		t.Fatalf("transport = %q, want the http fallback", srv.Transport())
	}

	resp, err := client.Get("http://localhost/api/v1/status")
	if err != nil {
		t.Fatalf("GET status over fallback: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status over fallback = %d, want 200", resp.StatusCode)
	}

	mutate, err := client.Post("http://localhost/api/v1/isolate", "application/json", nil)
	if err != nil {
		t.Fatalf("POST isolate over fallback: %v", err)
	}
	defer mutate.Body.Close()
	if mutate.StatusCode != http.StatusNotImplemented {
		t.Fatalf("isolate over fallback = %d, want 501", mutate.StatusCode)
	}
	if ctrl.isolates.Load() != 0 {
		t.Fatal("isolate ran over a transport that cannot identify its caller")
	}
}

// TestScanRequestValidation exercises the handler directly. End to end the
// route is root-only, and the body is never reached by an unprivileged caller.
func TestScanRequestValidation(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name     string
		body     string
		scanErr  error
		wantCode int
	}{
		{"a path is required", `{}`, nil, http.StatusBadRequest},
		{"a malformed body is rejected", `{`, nil, http.StatusBadRequest},
		{"a valid request is scanned", `{"path":"/bin/sh"}`, nil, http.StatusOK},
		{"a disabled scanner answers 503", `{"path":"/bin/sh"}`, ErrUnavailable, http.StatusServiceUnavailable},
		{"a scan failure answers 500", `{"path":"/bin/sh"}`, errors.New("read /bin/sh: io error"), http.StatusInternalServerError},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			ctrl := &fakeController{scanErr: tc.scanErr}
			srv, err := New(ctrl, Config{
				SocketPath: filepath.Join(t.TempDir(), "control.sock"),
				StatusFile: filepath.Join(t.TempDir(), "status.json"),
				Logger:     slog.New(slog.NewTextHandler(io.Discard, nil)),
			})
			if err != nil {
				t.Fatalf("New: %v", err)
			}
			rec := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodPost, "/api/v1/scan", strings.NewReader(tc.body))
			srv.handleScan(rec, req)
			if rec.Code != tc.wantCode {
				t.Fatalf("handleScan(%s) = %d (%s), want %d", tc.body, rec.Code, rec.Body.String(), tc.wantCode)
			}
		})
	}
}

func TestServerPublishesStatusFileOnStart(t *testing.T) {
	ctrl := &fakeController{
		status:     Status{Status: "running", Version: "9.9.9", Uptime: "1m0s", AlertsGenerated: 5, Isolated: true},
		enrollment: Enrollment{Enrolled: true, AgentID: "agent-7", IngestHost: "ingest:443"},
	}
	srv, _ := newTestServer(t, ctrl, Config{})

	var (
		public PublicStatus
		avail  Availability
	)
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		var err error
		public, avail, err = ReadStatusFile(srv.StatusFile(), time.Minute)
		if err == nil && avail == StatusOK {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if avail != StatusOK {
		t.Fatalf("status file availability = %q, want ok", avail)
	}
	if !public.Enrolled || public.AgentID != "agent-7" || public.IngestHost != "ingest:443" {
		t.Fatalf("status file lost enrollment: %+v", public)
	}
	if public.Service != ServiceRunning {
		t.Fatalf("status file service = %q, want running", public.Service)
	}
	if public.Version != "9.9.9" || public.Detections != 5 || !public.Isolated {
		t.Fatalf("status file lost runtime fields: %+v", public)
	}
}

func TestWrongMethodIsRejected(t *testing.T) {
	ctrl := &fakeController{}
	_, client := newTestServer(t, ctrl, Config{})
	resp, err := client.Post("http://localhost/api/v1/status", "application/json", nil)
	if err != nil {
		t.Fatalf("POST status: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("POST /api/v1/status = %d, want 405", resp.StatusCode)
	}
}

func TestNewRejectsNilController(t *testing.T) {
	t.Parallel()
	if _, err := New(nil, Config{}); err == nil {
		t.Fatal("New(nil) must fail")
	}
}

func TestCloseRemovesTheSocket(t *testing.T) {
	ctrl := &fakeController{}
	dir := shortTempDir(t)
	socket := filepath.Join(dir, "control.sock")
	srv, _ := newTestServer(t, ctrl, Config{SocketPath: socket, StatusFile: filepath.Join(dir, "status.json")})
	if srv.Transport() != transportSocket {
		t.Skipf("no socket transport in this environment (%s)", srv.Transport())
	}
	if err := srv.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if _, err := os.Stat(socket); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("socket still present after Close: %v", err)
	}
}

// TestCloseWithdrawsTheStatusFile pins the shutdown story: a stopped agent
// reads as not running, not as a status that slowly goes stale.
func TestCloseWithdrawsTheStatusFile(t *testing.T) {
	ctrl := &fakeController{status: Status{Status: "running"}}
	srv, _ := newTestServer(t, ctrl, Config{})

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if _, avail, err := ReadStatusFile(srv.StatusFile(), time.Minute); err == nil && avail == StatusOK {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if err := srv.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	_, avail, _ := ReadStatusFile(srv.StatusFile(), time.Minute)
	if avail != StatusMissing {
		t.Fatalf("availability after Close = %q, want %q", avail, StatusMissing)
	}
}
