package localapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"os"
	"runtime"
	"sync"
	"time"

	"github.com/razatechofficial/edr/internal/platform"
)

const (
	// DefaultHTTPAddr is the loopback fallback edrctl uses when no socket is
	// present. It is read-only: see the package comment.
	DefaultHTTPAddr = "127.0.0.1:9200"
	// DefaultSocketGroup owns the control socket together with root.
	DefaultSocketGroup = "edr"

	transportSocket = "unix"
	transportHTTP   = "http"
)

var (
	// ErrNoSocketTransport means no Unix domain socket can be created on this
	// platform, so the HTTP fallback is the only transport.
	ErrNoSocketTransport = errors.New("localapi: no socket transport on this platform")
	// ErrUnavailable is for a route whose subsystem is not enabled in this
	// agent's config. A controller wraps it so the API answers 503 instead of
	// reporting a failure that never ran.
	ErrUnavailable = errors.New("localapi: subsystem unavailable")
)

// Config configures the local control server. Zero fields take the platform
// defaults.
type Config struct {
	// SocketPath is the Unix domain socket. Empty uses DefaultSocketPath();
	// on a platform with no socket transport the server uses HTTPAddr.
	SocketPath string
	// HTTPAddr is the loopback fallback, used only when the socket cannot be
	// created.
	HTTPAddr string
	// StatusFile is the world-readable status document. Empty uses
	// DefaultStatusFile().
	StatusFile string
	// StatusInterval is how often the status file is rewritten.
	StatusInterval time.Duration
	// SocketGroup owns the socket with root. Empty uses DefaultSocketGroup.
	SocketGroup string
	Logger      *slog.Logger
}

// Server serves the agent's local control routes and keeps the status file
// current.
type Server struct {
	ctrl Controller
	cfg  Config
	log  *slog.Logger

	httpSrv   *http.Server
	ln        net.Listener
	transport string
	publish   chan struct{}
	done      chan struct{}
	stopOnce  sync.Once
}

// DefaultSocketPath returns the control socket edrctl already looks for.
//
// It is not under the agent data dir, although that would otherwise be the
// natural home: the data dir is not world-traversable and its location lives
// in a root-only config, so an unprivileged caller could not find, let alone
// reach, a socket placed there. The path has to be well known.
func DefaultSocketPath() string {
	if runtime.GOOS == "windows" {
		return ""
	}
	return platform.ControlSocket()
}

// New builds a server for ctrl.
func New(ctrl Controller, cfg Config) (*Server, error) {
	if ctrl == nil {
		return nil, errors.New("localapi: nil controller")
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.SocketPath == "" {
		cfg.SocketPath = DefaultSocketPath()
	}
	if cfg.HTTPAddr == "" {
		cfg.HTTPAddr = DefaultHTTPAddr
	}
	if cfg.StatusFile == "" {
		cfg.StatusFile = DefaultStatusFile()
	}
	if cfg.StatusInterval <= 0 {
		cfg.StatusInterval = DefaultStatusInterval
	}
	if cfg.SocketGroup == "" {
		cfg.SocketGroup = DefaultSocketGroup
	}
	return &Server{
		ctrl:    ctrl,
		cfg:     cfg,
		log:     cfg.Logger,
		publish: make(chan struct{}, 1),
		done:    make(chan struct{}),
	}, nil
}

// Start binds the transport, serves the routes and begins publishing the
// status file. It does not block; the caller closes the server, or cancels
// ctx, to stop it.
func (s *Server) Start(ctx context.Context) error {
	ln, transport, err := s.listen()
	if err != nil {
		return err
	}
	s.ln, s.transport = ln, transport

	s.httpSrv = &http.Server{
		Handler:           s.routes(),
		ReadHeaderTimeout: 5 * time.Second,
		// The peer credentials of a mutating call are read from the
		// connection, so the handler needs the connection and not just the
		// request.
		ConnContext: func(ctx context.Context, c net.Conn) context.Context {
			return context.WithValue(ctx, connContextKey{}, c)
		},
	}

	go func() {
		if err := s.httpSrv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			s.log.Error("local control api stopped", "transport", s.transport, "error", err)
		}
	}()
	go s.runStatusWriter(ctx)
	go func() {
		<-ctx.Done()
		s.Close()
	}()
	return nil
}

// listen prefers the socket and falls back to loopback HTTP, logging which
// one is in use and why.
func (s *Server) listen() (net.Listener, string, error) {
	if s.cfg.SocketPath != "" {
		ln, mode, err := listenControlSocket(s.cfg.SocketPath, s.cfg.SocketGroup)
		if err == nil {
			s.log.Info("local control api listening",
				"transport", transportSocket,
				"socket", s.cfg.SocketPath,
				"mode", fmt.Sprintf("%#o", fs.FileMode(mode).Perm()),
				"group", s.cfg.SocketGroup,
			)
			return ln, transportSocket, nil
		}
		s.log.Warn("local control socket unavailable, falling back to loopback http",
			"socket", s.cfg.SocketPath,
			"error", err,
		)
	}
	ln, err := net.Listen("tcp", s.cfg.HTTPAddr)
	if err != nil {
		return nil, "", fmt.Errorf("localapi: listen on %s: %w", s.cfg.HTTPAddr, err)
	}
	s.log.Warn("local control api listening on loopback http fallback; mutating routes are refused because the caller cannot be identified",
		"transport", transportHTTP,
		"addr", s.cfg.HTTPAddr,
	)
	return ln, transportHTTP, nil
}

// Transport reports which listener is in use: "unix" or "http".
func (s *Server) Transport() string { return s.transport }

// Addr reports the bound address, or nil before Start.
func (s *Server) Addr() net.Addr {
	if s.ln == nil {
		return nil
	}
	return s.ln.Addr()
}

// StatusFile reports the path of the published status file.
func (s *Server) StatusFile() string { return s.cfg.StatusFile }

// Publish asks for an immediate status file write. It never blocks: a write
// is already pending if the buffer is full.
func (s *Server) Publish() {
	select {
	case s.publish <- struct{}{}:
	default:
	}
}

// Close stops the listener, removes the socket and withdraws the status file.
//
// Withdrawing the status file is the point: a clean shutdown should read as
// "the agent is not running" immediately rather than as a status that slowly
// goes stale. A crash leaves the file behind, and staleness covers that.
func (s *Server) Close() error {
	var err error
	s.stopOnce.Do(func() {
		close(s.done)
		if s.httpSrv != nil {
			shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			err = s.httpSrv.Shutdown(shutCtx)
		}
		if s.transport == transportSocket && s.cfg.SocketPath != "" {
			if rmErr := os.Remove(s.cfg.SocketPath); rmErr != nil && !errors.Is(rmErr, fs.ErrNotExist) {
				s.log.Debug("control socket cleanup", "socket", s.cfg.SocketPath, "error", rmErr)
			}
		}
		if s.cfg.StatusFile != "" {
			if rmErr := os.Remove(s.cfg.StatusFile); rmErr != nil && !errors.Is(rmErr, fs.ErrNotExist) {
				s.log.Debug("status file cleanup", "path", s.cfg.StatusFile, "error", rmErr)
			}
		}
	})
	return err
}

// runStatusWriter publishes the status file on an interval and whenever
// Publish is called after a state change.
func (s *Server) runStatusWriter(ctx context.Context) {
	s.writeStatus(ctx)
	t := time.NewTicker(s.cfg.StatusInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-s.done:
			return
		case <-t.C:
			s.writeStatus(ctx)
		case <-s.publish:
			s.writeStatus(ctx)
		}
	}
}

func (s *Server) writeStatus(ctx context.Context) {
	st := s.ctrl.Status(ctx)
	en := s.ctrl.Enrollment(ctx)
	// The file is only written by a live agent, so the service is running by
	// construction. A reader that finds the file missing or stale knows the
	// agent is not reporting, which is a different state entirely.
	if err := WriteStatusFile(s.cfg.StatusFile, PublicFrom(st, en, ServiceRunning)); err != nil {
		s.log.Warn("status file write failed", "path", s.cfg.StatusFile, "error", err)
	}
}

// connContextKey carries the accepted connection into the request context.
type connContextKey struct{}

func (s *Server) routes() http.Handler {
	mux := http.NewServeMux()
	// /status is unprivileged: any caller that can reach the transport may
	// read it. Unprivileged consumers normally read the status file instead,
	// because the socket is root:edr.
	mux.HandleFunc("GET /api/v1/status", s.handleStatus)
	mux.Handle("POST /api/v1/scan", s.requireRoot(http.HandlerFunc(s.handleScan)))
	mux.Handle("POST /api/v1/isolate", s.requireRoot(http.HandlerFunc(s.handleIsolate)))
	mux.Handle("POST /api/v1/release", s.requireRoot(http.HandlerFunc(s.handleRelease)))
	mux.Handle("POST /api/v1/forensics/collect", s.requireRoot(http.HandlerFunc(s.handleForensics)))
	mux.Handle("POST /api/v1/rules/update", s.requireRoot(http.HandlerFunc(s.handleRulesUpdate)))
	return mux
}

// requireRoot refuses a mutating route unless the kernel names the caller as
// root. Nothing in the request is consulted: a caller that can reach the
// socket controls every byte of it.
func (s *Server) requireRoot(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, ok := r.Context().Value(connContextKey{}).(net.Conn)
		if !ok {
			writeTextError(w, http.StatusForbidden, ErrPeerCredsUnsupported.Error())
			return
		}
		peer, credErr := peerOf(conn)
		if err := authorizePeer(peer, credErr); err != nil {
			s.log.Warn("local control api refused a privileged route",
				"route", r.URL.Path,
				"transport", s.transport,
				"peer_uid", peer.UID,
				"peer_pid", peer.PID,
				"error", err,
			)
			code := http.StatusForbidden
			if errors.Is(err, ErrPeerCredsUnsupported) {
				code = http.StatusNotImplemented
			}
			writeTextError(w, code, err.Error())
			return
		}
		s.log.Info("local control api privileged route",
			"route", r.URL.Path,
			"peer_pid", peer.PID,
		)
		next.ServeHTTP(w, r)
	})
}

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.ctrl.Status(r.Context()))
}

func (s *Server) handleScan(w http.ResponseWriter, r *http.Request) {
	var req ScanRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&req); err != nil {
		writeTextError(w, http.StatusBadRequest, fmt.Sprintf("decoding scan request: %v", err))
		return
	}
	if req.Path == "" {
		writeTextError(w, http.StatusBadRequest, "scan request requires a path")
		return
	}
	res, err := s.ctrl.Scan(r.Context(), req.Path)
	if err != nil {
		writeControllerError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, res)
}

func (s *Server) handleIsolate(w http.ResponseWriter, r *http.Request) {
	s.action(w, r, "isolate", s.ctrl.Isolate)
}

func (s *Server) handleRelease(w http.ResponseWriter, r *http.Request) {
	s.action(w, r, "release", s.ctrl.Release)
}

func (s *Server) handleForensics(w http.ResponseWriter, r *http.Request) {
	s.action(w, r, "forensics_collect", s.ctrl.CollectForensics)
}

func (s *Server) handleRulesUpdate(w http.ResponseWriter, r *http.Request) {
	s.action(w, r, "rules_update", s.ctrl.UpdateRules)
}

// action runs one mutating operation and republishes the status file, so a
// containment change is visible to the UI without waiting for the interval.
func (s *Server) action(w http.ResponseWriter, r *http.Request, name string, run func(context.Context) (string, error)) {
	msg, err := run(r.Context())
	if err != nil {
		s.log.Error("local control api action failed", "action", name, "error", err)
		writeControllerError(w, err)
		return
	}
	s.Publish()
	writeJSON(w, http.StatusOK, ActionResult{Success: true, Message: msg, Action: name})
}

func writeJSON(w http.ResponseWriter, code int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	if err := json.NewEncoder(w).Encode(payload); err != nil {
		// The status line is already written; there is nothing left to say to
		// the client.
		return
	}
}

// writeTextError answers with a plain-text reason, which is what edrctl folds
// into its error message.
func writeTextError(w http.ResponseWriter, code int, msg string) {
	http.Error(w, msg, code)
}

// writeControllerError maps a controller failure to a status code. A disabled
// subsystem is 503 and not 500: nothing went wrong, the capability is not
// configured.
func writeControllerError(w http.ResponseWriter, err error) {
	code := http.StatusInternalServerError
	if errors.Is(err, ErrUnavailable) {
		code = http.StatusServiceUnavailable
	}
	writeTextError(w, code, err.Error())
}
