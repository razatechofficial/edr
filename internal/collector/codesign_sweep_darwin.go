//go:build darwin

package collector

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"strings"
	"sync/atomic"
	"time"

	"github.com/razatechofficial/edr/internal/config"
	"github.com/razatechofficial/edr/internal/schema"
)

var reCodesignTeam = regexp.MustCompile(`(?m)TeamIdentifier\s*=\s*([^\s]+)`)
var reCodesignID = regexp.MustCompile(`(?m)Identifier\s*=\s*([^\s]+)`)

// CodesignSweepDarwinSource runs periodic codesign verification on running process binaries.
type CodesignSweepDarwinSource struct {
	endpointID string
	hostname   string
	cfg        config.Config

	eventsTotal     atomic.Uint64
	lastUnix        atomic.Int64
	uniqueBins      atomic.Uint64
	verifyFailTotal atomic.Uint64
	spctlReject     atomic.Uint64
}

func NewCodesignSweepDarwinSource(endpointID, hostname string, cfg config.Config) *CodesignSweepDarwinSource {
	if hostname == "" {
		hostname, _ = os.Hostname()
	}
	return &CodesignSweepDarwinSource{endpointID: endpointID, hostname: hostname, cfg: cfg}
}

func (s *CodesignSweepDarwinSource) ExportMonitoringHealth() map[string]any {
	src := MonitoringSource{
		Name:          "codesign_sweep",
		OS:            runtime.GOOS,
		Source:        "codesign",
		Status:        "healthy",
		EPSOut:        s.eventsTotal.Load(),
		LastEventUnix: s.lastUnix.Load(),
	}.ToMap()
	src["enabled"] = s.cfg.Monitoring.MacosCodesignSweep
	src["codesign_unique_paths"] = s.uniqueBins.Load()
	src["codesign_failed_total"] = s.verifyFailTotal.Load()
	src["codesign_spctl_rejected_total"] = s.spctlReject.Load()
	return src
}

func (s *CodesignSweepDarwinSource) Run(ctx context.Context, sink *StreamingSink) error {
	if !s.cfg.Monitoring.MacosCodesignSweep {
		return nil
	}
	if _, err := exec.LookPath("codesign"); err != nil {
		return nil
	}
	iv := s.cfg.Monitoring.MacosCodesignIntervalSec
	if iv <= 0 {
		iv = 600
	}
	t := time.NewTicker(time.Duration(iv) * time.Second)
	defer t.Stop()
	s.sweep(ctx, sink)
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
			s.sweep(ctx, sink)
		}
	}
}

func (s *CodesignSweepDarwinSource) sweep(ctx context.Context, sink *StreamingSink) {
	now := time.Now().UTC()
	s.lastUnix.Store(now.Unix())
	cmd := exec.CommandContext(ctx, "ps", "-axo", "pid=,command=")
	out, err := cmd.Output()
	if err != nil {
		return
	}
	seen := map[string]struct{}{}
	un := uint64(0)
	max := s.cfg.Monitoring.MacosCodesignMaxProcs
	lines := bytes.Split(out, []byte{'\n'})
	n := 0
	for _, ln := range lines {
		if ctx.Err() != nil {
			return
		}
		if max > 0 && n >= max {
			break
		}
		fields := strings.Fields(string(ln))
		if len(fields) < 2 {
			continue
		}
		path := fields[1]
		if !strings.HasPrefix(path, "/") {
			continue
		}
		if _, ok := seen[path]; ok {
			continue
		}
		seen[path] = struct{}{}
		un++
		n++
		if _, err := os.Stat(path); err != nil {
			continue
		}
		c := exec.CommandContext(ctx, "codesign", "--verify", "--verbose=2", path)
		verifyFail := c.Run()
		display := runDisplay(ctx, path)
		team, ident := parseCodesignDisplay(display)
		tags := []string{"posture", "codesign_invalid"}
		if team != "" {
			tags = append(tags, "team-id:"+team)
		}
		if ident != "" {
			tags = append(tags, "identifier:"+ident)
		}
		notarized := strings.Contains(strings.ToLower(display), "notarized")
		tags = append(tags, "notarized:"+strconvBool(notarized))
		spOut, spErr := runSpctl(ctx, path)
		spBad := spErr != nil || strings.Contains(strings.ToLower(spOut), "rejected")
		if spBad {
			s.spctlReject.Add(1)
			if verifyFail == nil {
				s.eventsTotal.Add(1)
				s.emit(ctx, sink, now, path, "posture.spctl_rejected assess_failed output="+trimOneLine(spOut), "medium", []string{"posture", "spctl_rejected"})
			}
		}
		if verifyFail != nil {
			s.verifyFailTotal.Add(1)
			s.eventsTotal.Add(1)
			spVer := "spctl_ok"
			if spBad {
				spVer = "spctl_rejected"
			}
			pe := &schema.ProcessEvent{
				BaseEvent: schema.BaseEvent{
					SchemaVersion: schema.SchemaVersionV1,
					EventType:     schema.EventProcess,
					EndpointID:    s.endpointID,
					Timestamp:     now,
					Hostname:      s.hostname,
					OS:            runtime.GOOS,
				},
				ProcessName:   "posture",
				ProcessPath:   path,
				CommandLine:   "posture.codesign_invalid verify_failed team=" + team + " id=" + ident + " " + spVer + " display=" + trimOneLine(display),
				Tags:          tags,
				Severity:      "medium",
				SigningTeamID: team,
			}
			if sink != nil {
				_ = sink.Send(ctx, Telemetry{Process: pe})
			}
		}
	}
	s.uniqueBins.Store(un)
}

func runDisplay(ctx context.Context, path string) string {
	c := exec.CommandContext(ctx, "codesign", "--display", "--verbose=4", path)
	b, _ := c.CombinedOutput()
	return string(b)
}

func runSpctl(ctx context.Context, path string) (string, error) {
	if _, err := exec.LookPath("spctl"); err != nil {
		return "", err
	}
	c := exec.CommandContext(ctx, "spctl", "--assess", "--type", "execute", "-vv", path)
	b, err := c.CombinedOutput()
	return string(b), err
}

func parseCodesignDisplay(s string) (team, ident string) {
	if m := reCodesignTeam.FindStringSubmatch(s); len(m) > 1 {
		team = strings.TrimSpace(m[1])
	}
	if m := reCodesignID.FindStringSubmatch(s); len(m) > 1 {
		ident = strings.TrimSpace(m[1])
	}
	return team, ident
}

func strconvBool(v bool) string {
	if v {
		return "true"
	}
	return "false"
}

func trimOneLine(s string) string {
	s = strings.ReplaceAll(s, "\n", " ")
	if len(s) > 512 {
		return s[:512] + "..."
	}
	return strings.TrimSpace(s)
}

func (s *CodesignSweepDarwinSource) emit(ctx context.Context, sink *StreamingSink, ts time.Time, path, cmdline, sev string, tags []string) {
	s.eventsTotal.Add(1)
	pe := &schema.ProcessEvent{
		BaseEvent: schema.BaseEvent{
			SchemaVersion: schema.SchemaVersionV1,
			EventType:     schema.EventProcess,
			EndpointID:    s.endpointID,
			Timestamp:     ts,
			Hostname:      s.hostname,
			OS:            runtime.GOOS,
		},
		ProcessName: "posture",
		ProcessPath: path,
		CommandLine: cmdline,
		Tags:        tags,
		Severity:    sev,
	}
	if sink != nil {
		_ = sink.Send(ctx, Telemetry{Process: pe})
	}
}
