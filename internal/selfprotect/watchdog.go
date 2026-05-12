package selfprotect

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"time"

	"go.uber.org/zap"
)

const (
	defaultCheckInterval = 100 * time.Millisecond
	heartbeatTimeout     = time.Second
	defaultSocketPath    = "/var/run/edr/watchdog.sock"
)

// Watchdog monitors the agent process and restarts it if killed.
// It also monitors itself — the agent checks that the watchdog is alive
// via a Unix domain socket health-check protocol.
type Watchdog struct {
	agentPID      int
	agentPath     string
	agentArgs     []string
	socketPath    string
	listener      net.Listener
	logger        *zap.Logger
	checkInterval time.Duration

	mu     sync.Mutex
	running bool
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

// NewWatchdog creates a Watchdog that guards the agent binary at agentPath.
// The watchdog will restart the agent with agentArgs if the process dies.
func NewWatchdog(agentPath string, agentArgs []string, logger *zap.Logger) *Watchdog {
	return &Watchdog{
		agentPath:     agentPath,
		agentArgs:     agentArgs,
		socketPath:    defaultSocketPath,
		logger:        logger,
		checkInterval: defaultCheckInterval,
	}
}

// Start begins the watchdog loop. It creates a Unix domain socket for
// health checks and polls the agent process at the configured interval.
// If the agent dies, the watchdog restarts it within 100ms.
func (w *Watchdog) Start(ctx context.Context) error {
	w.mu.Lock()
	if w.running {
		w.mu.Unlock()
		return fmt.Errorf("watchdog: already running")
	}
	w.running = true
	w.mu.Unlock()

	if err := os.MkdirAll(filepath.Dir(w.socketPath), 0750); err != nil {
		w.setRunning(false)
		return fmt.Errorf("watchdog: create socket dir: %w", err)
	}
	os.Remove(w.socketPath)

	ln, err := net.Listen("unix", w.socketPath)
	if err != nil {
		w.setRunning(false)
		return fmt.Errorf("watchdog: listen on %s: %w", w.socketPath, err)
	}
	w.listener = ln

	ctx, w.cancel = context.WithCancel(ctx)

	w.wg.Add(2)
	go w.acceptLoop(ctx)
	go w.monitorLoop(ctx)

	w.logger.Info("watchdog started",
		zap.String("socket", w.socketPath),
		zap.String("agent_path", w.agentPath),
	)
	return nil
}

// Stop tears down the watchdog, closing the health-check socket and stopping
// all monitoring goroutines.
func (w *Watchdog) Stop() error {
	w.mu.Lock()
	if !w.running {
		w.mu.Unlock()
		return nil
	}
	w.running = false
	w.mu.Unlock()

	if w.cancel != nil {
		w.cancel()
	}
	if w.listener != nil {
		w.listener.Close()
	}
	w.wg.Wait()
	os.Remove(w.socketPath)
	w.logger.Info("watchdog stopped")
	return nil
}

// HealthCheck tests whether the watchdog is responsive by dialing its Unix
// domain socket and performing a ping/pong handshake.
func (w *Watchdog) HealthCheck() error {
	conn, err := net.DialTimeout("unix", w.socketPath, heartbeatTimeout)
	if err != nil {
		return fmt.Errorf("watchdog: health check dial: %w", err)
	}
	defer conn.Close()

	if err := conn.SetDeadline(time.Now().Add(heartbeatTimeout)); err != nil {
		return fmt.Errorf("watchdog: set deadline: %w", err)
	}
	if _, err := conn.Write([]byte("ping")); err != nil {
		return fmt.Errorf("watchdog: health check write: %w", err)
	}

	buf := make([]byte, 4)
	n, err := conn.Read(buf)
	if err != nil {
		return fmt.Errorf("watchdog: health check read: %w", err)
	}
	if string(buf[:n]) != "pong" {
		return fmt.Errorf("watchdog: unexpected response: %q", buf[:n])
	}
	return nil
}

// RestartAgent kills the currently tracked agent process and starts a new
// instance. Returns an error if the new process fails to launch.
func (w *Watchdog) RestartAgent() error {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.agentPID > 0 {
		if proc, err := os.FindProcess(w.agentPID); err == nil {
			_ = proc.Kill()
			_, _ = proc.Wait()
		}
		w.logger.Warn("killed agent for restart", zap.Int("old_pid", w.agentPID))
	}
	return w.startAgentLocked()
}

func (w *Watchdog) setRunning(v bool) {
	w.mu.Lock()
	w.running = v
	w.mu.Unlock()
}

func (w *Watchdog) startAgentLocked() error {
	cmd := exec.Command(w.agentPath, w.agentArgs...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("watchdog: start agent: %w", err)
	}
	w.agentPID = cmd.Process.Pid
	w.logger.Info("agent started", zap.Int("pid", w.agentPID))
	go func() { _ = cmd.Wait() }()
	return nil
}

func (w *Watchdog) acceptLoop(ctx context.Context) {
	defer w.wg.Done()
	for {
		conn, err := w.listener.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			continue
		}
		go w.handleConn(conn)
	}
}

func (w *Watchdog) handleConn(conn net.Conn) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(heartbeatTimeout))

	buf := make([]byte, 64)
	n, err := conn.Read(buf)
	if err != nil {
		return
	}
	switch string(buf[:n]) {
	case "ping":
		_, _ = conn.Write([]byte("pong"))
	case "heartbeat":
		_, _ = conn.Write([]byte("ack"))
	}
}

func (w *Watchdog) monitorLoop(ctx context.Context) {
	defer w.wg.Done()
	ticker := time.NewTicker(w.checkInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			w.mu.Lock()
			pid := w.agentPID
			w.mu.Unlock()

			if pid <= 0 {
				continue
			}
			if !processAlive(pid) {
				w.logger.Error("agent process died, restarting", zap.Int("dead_pid", pid))
				w.mu.Lock()
				if err := w.startAgentLocked(); err != nil {
					w.logger.Error("failed to restart agent", zap.Error(err))
				}
				w.mu.Unlock()
			}
		}
	}
}

// processAlive is implemented per-platform. The Unix implementation uses
// signal 0 as a non-destructive liveness probe; the Windows implementation
// (watchdog_windows.go) uses OpenProcess + GetExitCodeProcess.
