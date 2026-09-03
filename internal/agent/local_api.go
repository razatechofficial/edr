package agent

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"os"
	"runtime"
	"time"

	"github.com/razatechofficial/edr/internal/platform"
)

// startLocalControlAPI serves edrctl's local control interface
// (unix socket / named path + 127.0.0.1:9200) so "Control API: unavailable"
// is not shown while the sensor is healthy.
func (a *Agent) startLocalControlAPI(ctx context.Context) {
	if a == nil {
		return
	}
	a.startedAt = time.Now()
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/status", a.handleLocalStatus)

	newServer := func() *http.Server {
		return &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	}

	if runtime.GOOS != "windows" {
		sock := platform.ControlSocket()
		_ = os.Remove(sock)
		ln, err := net.Listen("unix", sock)
		if err != nil {
			a.logger.Warn("local control socket listen failed", "path", sock, "error", err)
		} else {
			_ = os.Chmod(sock, 0o660)
			srv := newServer()
			go func() {
				<-ctx.Done()
				_ = srv.Close()
			}()
			a.logger.Info("local control API listening", "socket", sock)
			go func() {
				if err := srv.Serve(ln); err != nil && err != http.ErrServerClosed && ctx.Err() == nil {
					a.logger.Warn("local control socket serve stopped", "error", err)
				}
				_ = os.Remove(sock)
			}()
		}
	}

	httpLn, err := net.Listen("tcp", "127.0.0.1:9200")
	if err != nil {
		a.logger.Warn("local control HTTP listen failed", "addr", "127.0.0.1:9200", "error", err)
		return
	}
	srv := newServer()
	go func() {
		<-ctx.Done()
		_ = srv.Close()
	}()
	a.logger.Info("local control API listening", "addr", "http://127.0.0.1:9200")
	go func() {
		if err := srv.Serve(httpLn); err != nil && err != http.ErrServerClosed && ctx.Err() == nil {
			a.logger.Warn("local control HTTP serve stopped", "error", err)
		}
	}()
}

func (a *Agent) handleLocalStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	uptime := time.Since(a.startedAt)
	if a.startedAt.IsZero() {
		uptime = 0
	}
	rules := 0
	if a.ruleSet.Rules != nil {
		rules = len(a.ruleSet.Rules)
	}
	alerts := uint64(0)
	if a.advEngine != nil {
		alerts = a.advEngine.Stats().DetectionsEmitted
	}
	body := map[string]any{
		"status":            "running",
		"version":           a.cfg.Agent.Version,
		"uptime":            uptime.Round(time.Second).String(),
		"started_at":        a.startedAt.UTC().Format(time.RFC3339),
		"pid":               os.Getpid(),
		"os":                runtime.GOOS,
		"arch":              runtime.GOARCH,
		"rules_count":       rules,
		"cpu_percent":       0.0,
		"memory_mb":         0.0,
		"events_processed":  a.eventsProcessed.Load(),
		"alerts_generated":  alerts,
		"isolated":          false,
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(body)
}
