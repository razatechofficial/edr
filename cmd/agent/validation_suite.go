package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/razatechofficial/edr/internal/agent"
	"github.com/razatechofficial/edr/internal/config"
	"github.com/razatechofficial/edr/internal/detection"
)

type ValidationTest struct {
	Name         string
	Description  string
	MITRE        string
	Severity     string
	Simulate     func(ctx context.Context) error
	Verify       func(ctx context.Context, detections []detection.Detection) bool
	Cleanup      func()
	TimeoutSec   int
	SupportedOS  []string
	RequiresRoot bool
	SkipInCI     bool
	Optional     bool
}

type TestResult struct {
	TestName           string
	MITRE              string
	Passed             bool
	FailReason         string
	DetectionLatencyMs int64
	ResponseAction     string
	Skipped            bool
	Optional           bool
}

type ValidationSink struct {
	ch  chan detection.Detection
	mu  sync.Mutex
	all []detection.Detection
}

func NewValidationSink() *ValidationSink {
	return &ValidationSink{ch: make(chan detection.Detection, 1000)}
}

func (s *ValidationSink) Send(d detection.Detection) {
	if s == nil {
		return
	}
	select {
	case s.ch <- d:
	default:
	}
	s.mu.Lock()
	s.all = append(s.all, d)
	s.mu.Unlock()
}

func (s *ValidationSink) DrainSince(t time.Time) []detection.Detection {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]detection.Detection, 0, len(s.all))
	for _, d := range s.all {
		if !d.Timestamp.Before(t) {
			out = append(out, d)
		}
	}
	return out
}

type ValidationReport struct {
	Timestamp    time.Time    `json:"timestamp"`
	AgentVersion string       `json:"agent_version"`
	Hostname     string       `json:"hostname"`
	OS           string       `json:"os"`
	Results      []TestResult `json:"results"`
	Passed       int          `json:"passed"`
	Failed       int          `json:"failed"`
	TotalMs      int64        `json:"total_ms"`
}

func runValidationSuite(ctx context.Context, a *agent.Agent, cfg *config.Config) int {
	startWall := time.Now()
	fmt.Println("=== EDR Validation Suite ===")
	fmt.Printf("Version: %s\n\n", Version)

	preflightFail := preflightChecks(cfg)
	if len(preflightFail) > 0 {
		fmt.Println("Preflight failures:")
		for _, f := range preflightFail {
			fmt.Printf("  - %s\n", f)
		}
		writeValidationReport(cfg, ValidationReport{
			Timestamp:    time.Now().UTC(),
			AgentVersion: Version,
			Hostname:     hostname(),
			OS:           runtime.GOOS,
			Results: []TestResult{{
				TestName:   "preflight",
				MITRE:      "N/A",
				Passed:     false,
				FailReason: strings.Join(preflightFail, "; "),
			}},
			Passed:  0,
			Failed:  1,
			TotalMs: time.Since(startWall).Milliseconds(),
		})
		return 1
	}

	sink := NewValidationSink()
	a.SetValidationSink(sink.Send)
	defer a.SetValidationSink(nil)

	tests := buildValidationTests()
	results := make([]TestResult, 0, len(tests))
	passed, failed := 0, 0
	agentCtx, agentCancel := context.WithCancel(ctx)
	defer agentCancel()
	go func() { _ = a.Run(agentCtx) }()
	time.Sleep(3 * time.Second)
	for _, test := range tests {
		if skip, reason := shouldSkip(test); skip {
			fmt.Printf("[ SKIP ] %s (%s): %s\n", test.Name, test.MITRE, reason)
			results = append(results, TestResult{
				TestName:   test.Name,
				MITRE:      test.MITRE,
				Skipped:    true,
				FailReason: reason,
			})
			continue
		}
		fmt.Printf("[ RUN ] %s (%s)\n", test.Name, test.MITRE)
		result := runOneTest(ctx, sink, test)
		result.Optional = test.Optional
		results = append(results, result)
		if result.Passed {
			passed++
			fmt.Printf("[ PASS ] %s — detected in %dms\n", test.Name, result.DetectionLatencyMs)
		} else {
			if test.Optional {
				fmt.Printf("[ WARN ] %s — optional check not matched: %s\n", test.Name, result.FailReason)
			} else {
				failed++
				fmt.Printf("[ FAIL ] %s — %s\n", test.Name, result.FailReason)
			}
		}
		if test.Cleanup != nil {
			test.Cleanup()
		}
		time.Sleep(500 * time.Millisecond)
	}
	fmt.Printf("\n=== Results: %d/%d passed ===\n", passed, len(tests))
	for _, r := range results {
		status := "PASS"
		if !r.Passed && r.Optional {
			status = "WARN"
		} else if !r.Passed {
			status = "FAIL"
		}
		fmt.Printf("  [%s] %-40s %s latency=%dms\n", status, r.TestName, r.MITRE, r.DetectionLatencyMs)
	}
	monRep := runMonitoringValidation(ctx, cfg)
	writeMonitoringReport(cfg, monRep)
	if monRep.Failed > 0 {
		failed += monRep.Failed
	}
	if failed > 0 {
		fmt.Printf("\n%d tests FAILED\n", failed)
		writeValidationReport(cfg, ValidationReport{
			Timestamp:    time.Now().UTC(),
			AgentVersion: Version,
			Hostname:     hostname(),
			OS:           runtime.GOOS,
			Results:      results,
			Passed:       passed,
			Failed:       failed,
			TotalMs:      time.Since(startWall).Milliseconds(),
		})
		return 1
	}
	fmt.Println("\nAll tests passed")
	writeValidationReport(cfg, ValidationReport{
		Timestamp:    time.Now().UTC(),
		AgentVersion: Version,
		Hostname:     hostname(),
		OS:           runtime.GOOS,
		Results:      results,
		Passed:       passed,
		Failed:       failed,
		TotalMs:      time.Since(startWall).Milliseconds(),
	})
	return 0
}

func runOneTest(ctx context.Context, sink *ValidationSink, test ValidationTest) TestResult {
	startAt := time.Now()
	res := TestResult{TestName: test.Name, MITRE: test.MITRE}
	verify := test.Verify
	if verify == nil {
		verify = func(_ context.Context, detections []detection.Detection) bool {
			for _, d := range detections {
				if strings.Contains(d.TechniqueID, test.MITRE) {
					return true
				}
			}
			return false
		}
	}
	if err := test.Simulate(ctx); err != nil {
		res.FailReason = fmt.Sprintf("simulate error: %v", err)
		return res
	}
	deadline := time.Now().Add(time.Duration(test.TimeoutSec) * time.Second)
	for time.Now().Before(deadline) {
		select {
		case <-ctx.Done():
			res.FailReason = "context cancelled"
			return res
		default:
		}
		detections := sink.DrainSince(startAt)
		if verify(ctx, detections) {
			res.Passed = true
			res.DetectionLatencyMs = time.Since(startAt).Milliseconds()
			for _, d := range detections {
				if strings.Contains(d.TechniqueID, test.MITRE) || verify(ctx, []detection.Detection{d}) {
					res.ResponseAction = detectionSourceName(d.Source)
					break
				}
			}
			return res
		}
		time.Sleep(100 * time.Millisecond)
	}
	detections := sink.DrainSince(startAt)
	res.FailReason = fmt.Sprintf("timeout after %ds — %d detections received but none matched", test.TimeoutSec, len(detections))
	if len(detections) > 0 {
		techniques := make([]string, 0, len(detections))
		for _, d := range detections {
			techniques = append(techniques, d.TechniqueID)
		}
		res.FailReason += fmt.Sprintf(" (got: %s)", strings.Join(techniques, ", "))
	}
	return res
}

func buildValidationTests() []ValidationTest {
	eicarPath := filepath.Join(os.TempDir(), "eicar_test.txt")
	cronPath := filepath.Join(os.TempDir(), "edr_test_cron")
	ransomDir := filepath.Join(os.TempDir(), "edr_ransom_test")
	startupPath := suspiciousWritePath()
	return []ValidationTest{
		{
			Name:       "suspicious-process-spawn",
			MITRE:      "T1059",
			TimeoutSec: 10,
			Simulate: func(ctx context.Context) error {
				switch runtime.GOOS {
				case "windows":
					payload := base64.StdEncoding.EncodeToString([]byte("Write-Host 'edr-test'"))
					_ = exec.CommandContext(ctx, "powershell.exe", "-EncodedCommand", payload).Run()
				case "linux", "darwin":
					_ = exec.CommandContext(ctx, "sh", "-c", "echo edr-test | base64 | sh 2>/dev/null || true").Run()
				}
				return nil
			},
			Verify: func(_ context.Context, detections []detection.Detection) bool {
				for _, d := range detections {
					if strings.Contains(d.TechniqueID, "T1059") {
						return true
					}
				}
				return false
			},
			SupportedOS: []string{"linux", "darwin", "windows"},
			Optional:    true,
		},
		{
			Name:       "suspicious-file-write",
			MITRE:      "T1547",
			TimeoutSec: 10,
			Simulate: func(_ context.Context) error {
				_ = os.MkdirAll(filepath.Dir(startupPath), 0o755)
				return os.WriteFile(startupPath, []byte("#!/bin/sh\necho owned"), 0o755)
			},
			Cleanup:     func() { _ = os.Remove(startupPath) },
			SupportedOS: []string{"linux", "darwin", "windows"},
			Optional:    true,
		},
		{
			Name:       "yara-eicar-detection",
			MITRE:      "T1204",
			TimeoutSec: 15,
			Simulate: func(ctx context.Context) error {
				eicar := `X5O!P%@AP[4\PZX54(P^)7CC)7}` + `$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*`
				quoted := strings.ReplaceAll(eicar, `'`, `'\''`)
				cmd := exec.CommandContext(ctx, "sh", "-c", fmt.Sprintf("printf '%%s' '%s' > %q", quoted, eicarPath))
				return cmd.Run()
			},
			Verify: func(_ context.Context, detections []detection.Detection) bool {
				for _, d := range detections {
					if d.Source == detection.SourceYARA && strings.Contains(strings.ToLower(d.RuleID), "eicar") {
						return true
					}
				}
				return false
			},
			Cleanup:     func() { _ = os.Remove(eicarPath) },
			SupportedOS: []string{"linux", "darwin", "windows"},
		},
		{
			Name:       "suspicious-network-connection",
			MITRE:      "T1571",
			TimeoutSec: 10,
			Simulate: func(_ context.Context) error {
				conn, _ := net.DialTimeout("tcp", "127.0.0.1:4444", 2*time.Second)
				if conn != nil {
					_ = conn.Close()
				}
				return nil
			},
			SupportedOS: []string{"linux", "darwin", "windows"},
			Optional:    true,
		},
		{
			Name:        "process-injection-simulation",
			MITRE:       "T1055",
			TimeoutSec:  10,
			Simulate:    func(_ context.Context) error { return simulateSelfInjection() },
			SupportedOS: []string{"linux", "darwin", "windows"},
			Optional:    true,
		},
		{
			Name:        "sensitive-file-access",
			MITRE:       "T1552",
			TimeoutSec:  10,
			Simulate:    func(_ context.Context) error { return attemptSensitiveFileRead() },
			Verify: func(_ context.Context, detections []detection.Detection) bool {
				for _, d := range detections {
					if strings.Contains(d.TechniqueID, "T1003.008") || strings.Contains(strings.ToLower(d.RuleID), "cred-001") {
						return true
					}
				}
				return false
			},
			SupportedOS: []string{"linux", "darwin", "windows"},
			SkipInCI:    true,
		},
		{
			Name:       "ransomware-simulation",
			MITRE:      "T1486",
			TimeoutSec: 15,
			Simulate: func(_ context.Context) error {
				_ = os.MkdirAll(ransomDir, 0o755)
				for i := range 30 {
					src := filepath.Join(ransomDir, fmt.Sprintf("doc%d.docx", i))
					dst := filepath.Join(ransomDir, fmt.Sprintf("doc%d.locked", i))
					if err := os.WriteFile(src, []byte(strings.Repeat("X", 1024)), 0o644); err != nil {
						return err
					}
					if err := os.Rename(src, dst); err != nil {
						return fmt.Errorf("rename %d failed: %w", i, err)
					}
				}
				return nil
			},
			Cleanup:     func() { _ = os.RemoveAll(ransomDir) },
			SupportedOS: []string{"linux", "darwin", "windows"},
			Optional:    true,
		},
		{
			Name:       "persistence-cron",
			MITRE:      "T1053",
			TimeoutSec: 10,
			Simulate: func(_ context.Context) error {
				return os.WriteFile(cronPath, []byte("* * * * * /tmp/evil.sh"), 0o644)
			},
			Cleanup:     func() { _ = os.Remove(cronPath) },
			SupportedOS: []string{"linux", "darwin", "windows"},
			Optional:    true,
		},
	}
}

func suspiciousWritePath() string {
	home, _ := os.UserHomeDir()
	switch runtime.GOOS {
	case "windows":
		appData := os.Getenv("APPDATA")
		if appData == "" {
			appData = filepath.Join(home, "AppData", "Roaming")
		}
		return filepath.Join(appData, "Microsoft", "Windows", "Start Menu", "Programs", "Startup", "edr_test.bat")
	case "darwin":
		return filepath.Join(home, "Library", "LaunchAgents", "com.edr-test.plist")
	case "linux":
		return "/tmp/edr_test_cron_sim"
	default:
		return "/tmp/edr_test_startup"
	}
}

func simulateSelfInjection() error {
	switch runtime.GOOS {
	case "linux":
		f, err := os.OpenFile("/proc/self/mem", os.O_RDONLY, 0)
		if err != nil {
			return nil // syscall attempt is enough for test mode
		}
		_ = f.Close()
		return nil
	case "windows":
		return exec.Command("cmd", "/c", "echo", "self-injection-sim").Run()
	default:
		return exec.Command("sh", "-c", "echo self-injection-sim >/dev/null").Run()
	}
}

func attemptSensitiveFileRead() error {
	var targets []string
	switch runtime.GOOS {
	case "windows":
		targets = []string{`C:\Windows\System32\config\SAM`}
	case "darwin":
		targets = []string{"/Library/Application Support/com.apple.TCC/TCC.db"}
	default:
		targets = []string{"/etc/shadow"}
	}
	for _, p := range targets {
		_, _ = os.ReadFile(p) // permission denied still exercises file access path
	}
	return nil
}

func detectionSourceName(src detection.DetectionSource) string {
	switch src {
	case detection.SourceSigma:
		return "sigma"
	case detection.SourceYARA:
		return "yara"
	case detection.SourceBehavioral:
		return "behavioral"
	case detection.SourceML:
		return "ml"
	case detection.SourceDedup:
		return "dedup"
	default:
		return "unknown"
	}
}

func shouldSkip(test ValidationTest) (bool, string) {
	if len(test.SupportedOS) > 0 && !slices.Contains(test.SupportedOS, runtime.GOOS) {
		return true, fmt.Sprintf("not supported on %s", runtime.GOOS)
	}
	if test.RequiresRoot && !isPrivileged() {
		return true, "requires root/admin"
	}
	if test.SkipInCI && strings.EqualFold(os.Getenv("CI"), "true") {
		return true, "skipped in CI"
	}
	return false, ""
}

func isPrivileged() bool {
	if runtime.GOOS == "windows" {
		return true
	}
	return os.Geteuid() == 0
}

func preflightChecks(cfg *config.Config) []string {
	var failures []string
	sigmaDir := cfg.Detection.Sigma.RulesDir
	yaraDir := cfg.Detection.YARA.RulesDir
	if sigmaDir == "" || !dirExists(sigmaDir) {
		failures = append(failures, fmt.Sprintf("sigma rules_dir not found: %s", sigmaDir))
	} else if n := countFilesWithExt(sigmaDir, ".yml"); n == 0 {
		failures = append(failures, "no sigma rules found")
	} else {
		fmt.Printf("  sigma rules: %d\n", n)
	}
	if yaraDir == "" || !dirExists(yaraDir) {
		failures = append(failures, fmt.Sprintf("yara rules_dir not found: %s", yaraDir))
	} else if n := countFilesWithExt(yaraDir, ".yar"); n == 0 {
		failures = append(failures, "no yara rules found")
	} else {
		fmt.Printf("  yara rules:  %d\n", n)
	}
	pbPath := strings.TrimSpace(cfg.Response.PlaybooksPath)
	if pbPath == "" {
		pbDir := strings.TrimSpace(cfg.Response.PlaybooksDir)
		if pbDir == "" {
			pbDir = filepath.Join("rules", "playbooks")
		}
		pbPath = filepath.Join(pbDir, "playbooks.yml")
	}
	if _, err := os.Stat(pbPath); err != nil {
		failures = append(failures, fmt.Sprintf("playbooks not found: %s", pbPath))
	}
	return failures
}

func dirExists(path string) bool {
	st, err := os.Stat(path)
	return err == nil && st.IsDir()
}

func countFilesWithExt(root, ext string) int {
	n := 0
	_ = filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		if strings.EqualFold(filepath.Ext(path), ext) {
			n++
		}
		return nil
	})
	return n
}

func writeValidationReport(cfg *config.Config, rep ValidationReport) {
	data, err := json.MarshalIndent(rep, "", "  ")
	if err != nil {
		fmt.Printf("failed to serialize validation report: %v\n", err)
		return
	}
	out := filepath.Join(cfg.Agent.DataDir, "validation_report.json")
	if cfg.Agent.DataDir == "" {
		out = "/tmp/edr_validation_report.json"
	}
	_ = os.MkdirAll(filepath.Dir(out), 0o755)
	if err := os.WriteFile(out, data, 0o644); err != nil {
		fmt.Printf("failed to write validation report %s: %v\n", out, err)
	} else {
		fmt.Printf("validation report: %s\n", out)
	}
	_ = os.WriteFile("/tmp/edr_validation_report.json", data, 0o644)
}

func hostname() string {
	h, err := os.Hostname()
	if err != nil {
		return "unknown"
	}
	return h
}
