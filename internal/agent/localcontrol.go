package agent

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"runtime/metrics"
	"strings"
	"sync"
	"time"

	"github.com/razatechofficial/edr/internal/localapi"
	"github.com/razatechofficial/edr/internal/response"
)

// localControl adapts the Agent to [localapi.Controller].
//
// edrctl has always issued six requests to the agent's local control
// interface and the agent served none of them, so isolate, release, scan,
// forensics collect and rules update were inert and status could not fail.
// Everything the API answers is read from this process; nothing re-reads the
// root-owned config, because the whole point of the status file is that an
// unprivileged UI can see the same truth.
type localControl struct {
	agent     *Agent
	startedAt time.Time

	// cpuMu guards the previous CPU sample. CPUPercent is a rate, so it needs
	// the previous reading to mean anything.
	cpuMu        sync.Mutex
	lastCPUTotal float64
	lastCPUIdle  float64

	// isolationMarker records a locally requested isolation. The response
	// engine's own containment records cover playbook-driven isolation, but a
	// direct isolate through this API registers none, and an isolation that
	// the agent cannot report is an isolation nobody will remember to lift.
	isolationMarker string
}

// startLocalControl starts the local control server and the status file
// publisher. It returns the server so Run can close it on shutdown.
func (a *Agent) startLocalControl(ctx context.Context) (*localapi.Server, error) {
	if a == nil {
		return nil, errors.New("local control: nil agent")
	}
	ctrl := &localControl{
		agent:           a,
		startedAt:       time.Now(),
		isolationMarker: a.localIsolationMarkerPath(),
	}
	srv, err := localapi.New(ctrl, localapi.Config{Logger: a.logger})
	if err != nil {
		return nil, err
	}
	if err := srv.Start(ctx); err != nil {
		return nil, err
	}
	a.logger.Info("local control api started",
		"transport", srv.Transport(),
		"status_file", srv.StatusFile(),
	)
	return srv, nil
}

// localIsolationMarkerPath sits beside the response layer's containment
// state, so every record of an in-force containment lives in one place.
func (a *Agent) localIsolationMarkerPath() string {
	dir := a.cfg.Agent.DataDir
	if dir == "" {
		return ""
	}
	return filepath.Join(dir, "response", "local_isolation")
}

// Status reports live runtime counters. It touches no network and no config.
func (c *localControl) Status(_ context.Context) localapi.Status {
	a := c.agent
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)

	st := localapi.Status{
		Status:     "running",
		Version:    a.cfg.Agent.Version,
		StartedAt:  c.startedAt.UTC(),
		Uptime:     time.Since(c.startedAt).Round(time.Second).String(),
		PID:        os.Getpid(),
		OS:         runtime.GOOS,
		Arch:       runtime.GOARCH,
		RulesCount: a.controlPlaneRulesLoaded(),
		CPUPercent: c.cpuPercent(),
		MemoryMB:   float64(ms.Sys) / (1024 * 1024),
		Isolated:   c.isolated(),
	}
	if a.advEngine != nil {
		st.EventsProcessed = a.advEngine.Stats().EventsProcessed
	}
	st.AlertsGenerated = a.localAlerts.Load()
	return st
}

// Enrollment reports the agent id and ingest hosts. Both are identifiers, not
// credentials: the device certificate and the enrollment token stay in the
// keystore and are never named here.
func (c *localControl) Enrollment(_ context.Context) localapi.Enrollment {
	a := c.agent
	en := localapi.Enrollment{
		AgentID:    strings.TrimSpace(a.xdrState.AgentID),
		IngestHost: strings.Join(a.xdrState.IngestHosts, ","),
	}
	if en.AgentID == "" {
		en.AgentID = strings.TrimSpace(a.cfg.Agent.ID)
	}
	en.Enrolled = en.AgentID != "" && len(a.xdrState.IngestHosts) > 0
	return en
}

// Scan hashes one file, runs the YARA rules over it and checks the hash
// against the IOC databases and the threat intel feeds.
func (c *localControl) Scan(ctx context.Context, path string) (localapi.ScanResult, error) {
	a := c.agent
	start := time.Now()
	res := localapi.ScanResult{
		Path:       path,
		Hashes:     []string{},
		YARAHits:   []string{},
		IOCMatches: []string{},
	}

	hashCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	sum, err := hashFileWithTimeout(hashCtx, path)
	if err != nil {
		return res, fmt.Errorf("hashing %s: %w", path, err)
	}
	res.Hashes = append(res.Hashes, "sha256:"+sum)

	if a.advEngine == nil {
		res.Duration = time.Since(start).String()
		return res, fmt.Errorf("%w: advanced detection engine is not enabled, so %s was hashed but not scanned",
			localapi.ErrUnavailable, path)
	}
	for _, d := range a.advEngine.ScanFileForValidation(ctx, path) {
		name := d.RuleName
		if name == "" {
			name = d.RuleID
		}
		res.YARAHits = append(res.YARAHits, name)
	}
	if m := a.advEngine.IOCMatcher(); m != nil {
		if hit := m.CheckHash(sum); hit != nil && hit.Matched {
			res.IOCMatches = append(res.IOCMatches, fmt.Sprintf("%s (%s)", hit.Indicator, hit.Source))
		}
	}
	if a.threatIntel != nil {
		if hit, err := a.threatIntel.LookupIOC(sum); err == nil && hit != nil && hit.Found {
			res.IOCMatches = append(res.IOCMatches,
				fmt.Sprintf("%s (%s)", hit.IOC, strings.Join(hit.Sources, ",")))
		}
	}
	res.Clean = len(res.YARAHits) == 0 && len(res.IOCMatches) == 0
	res.Duration = time.Since(start).Round(time.Millisecond).String()
	return res, nil
}

// Isolate enforces host network isolation.
func (c *localControl) Isolate(ctx context.Context) (string, error) {
	msg, err := c.runResponseOp(ctx, response.OpNetworkIsolate, map[string]interface{}{"action": "isolate"})
	if err != nil {
		return "", err
	}
	c.setLocalIsolation(true)
	return msg, nil
}

// Release lifts host network isolation.
func (c *localControl) Release(ctx context.Context) (string, error) {
	msg, err := c.runResponseOp(ctx, response.OpNetworkRelease, map[string]interface{}{"action": "release"})
	if err != nil {
		return "", err
	}
	c.setLocalIsolation(false)
	return msg, nil
}

// CollectForensics builds a DFIR package from this host. The operator is
// recorded in the package manifest, which is what a chain of custody needs.
func (c *localControl) CollectForensics(ctx context.Context) (string, error) {
	return c.runResponseOp(ctx, response.OpCollectForensics, map[string]interface{}{
		"alert_id": "local-" + time.Now().UTC().Format("20060102T150405Z"),
		"operator": "edrctl",
	})
}

// UpdateRules reloads detection content from disk.
//
// It does not fetch from upstream: rule bundles reach an endpoint through the
// control plane's policy sync, which the server drives. What this route can
// honestly do is pick up content already written to the rules tree and report
// what is loaded afterwards.
func (c *localControl) UpdateRules(_ context.Context) (string, error) {
	a := c.agent
	if a.advEngine == nil {
		return "", fmt.Errorf("%w: advanced detection engine is not enabled, so there is nothing to reload",
			localapi.ErrUnavailable)
	}
	if err := a.advEngine.Reload(); err != nil {
		return "", fmt.Errorf("reloading detection rules: %w", err)
	}
	loaded := a.advEngine.Stats().RulesLoaded
	return fmt.Sprintf("reloaded detection rules from disk (sigma %d, yara %d, behavioral %d)",
		loaded.Sigma, loaded.YARA, loaded.Behavioral), nil
}

// runResponseOp executes one response operation and returns its message.
func (c *localControl) runResponseOp(ctx context.Context, op response.OpKey, params map[string]interface{}) (string, error) {
	eng := c.agent.respEngine
	if eng == nil {
		return "", fmt.Errorf("%w: the response engine is disabled; set response.auto_response in the agent config",
			localapi.ErrUnavailable)
	}
	result, err := eng.Execute(ctx, op, params)
	if err != nil {
		return "", fmt.Errorf("%s: %w", op, err)
	}
	if result == nil {
		return "", fmt.Errorf("%s: response engine returned no result", op)
	}
	if !result.Success {
		return "", fmt.Errorf("%s: %s", op, result.Message)
	}
	return result.Message, nil
}

// isolated reports whether this host is contained, by either route: a
// playbook-driven isolation the response layer is tracking, or one requested
// through this API.
func (c *localControl) isolated() bool {
	if layer := c.agent.responseLayer; layer != nil {
		for _, cm := range layer.ActiveContainments() {
			if cm.Action == response.ActionNetworkIsolate {
				return true
			}
		}
	}
	if c.isolationMarker == "" {
		return false
	}
	_, err := os.Stat(c.isolationMarker)
	return err == nil
}

// setLocalIsolation records or clears the local isolation marker so the state
// survives a restart of the agent that applied it.
func (c *localControl) setLocalIsolation(on bool) {
	if c.isolationMarker == "" {
		return
	}
	if !on {
		if err := os.Remove(c.isolationMarker); err != nil && !errors.Is(err, fs.ErrNotExist) {
			c.agent.logger.Warn("clearing local isolation marker failed",
				"path", c.isolationMarker, "error", err)
		}
		return
	}
	if err := os.MkdirAll(filepath.Dir(c.isolationMarker), 0o700); err != nil {
		c.agent.logger.Warn("recording local isolation failed",
			"path", c.isolationMarker, "error", err)
		return
	}
	body := []byte(time.Now().UTC().Format(time.RFC3339) + "\n")
	if err := os.WriteFile(c.isolationMarker, body, 0o600); err != nil {
		c.agent.logger.Warn("recording local isolation failed",
			"path", c.isolationMarker, "error", err)
	}
}

// cpuPercent is the share of available CPU this process used since the
// previous sample, normalised by GOMAXPROCS. The first call covers the whole
// run, so it reads as an average rather than a spike.
func (c *localControl) cpuPercent() float64 {
	samples := []metrics.Sample{
		{Name: "/cpu/classes/total:cpu-seconds"},
		{Name: "/cpu/classes/idle:cpu-seconds"},
	}
	metrics.Read(samples)
	if samples[0].Value.Kind() != metrics.KindFloat64 || samples[1].Value.Kind() != metrics.KindFloat64 {
		return 0
	}
	total, idle := samples[0].Value.Float64(), samples[1].Value.Float64()

	c.cpuMu.Lock()
	defer c.cpuMu.Unlock()
	deltaTotal := total - c.lastCPUTotal
	deltaIdle := idle - c.lastCPUIdle
	c.lastCPUTotal, c.lastCPUIdle = total, idle
	if deltaTotal <= 0 {
		return 0
	}
	busy := deltaTotal - deltaIdle
	if busy < 0 {
		busy = 0
	}
	return busy / deltaTotal * 100
}
