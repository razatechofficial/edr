package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"time"

	"github.com/razatechofficial/edr/internal/agent"
	"github.com/razatechofficial/edr/internal/config"
	"github.com/razatechofficial/edr/internal/detection"
	"github.com/razatechofficial/edr/internal/schema"
)

type ValidationTest struct {
	Name        string
	Description string
	MITRE       string
	Severity    string
	Simulate    func(ctx context.Context) error
	Verify      func(ctx context.Context, detections []detection.Detection) bool
	Cleanup     func()
	TimeoutSec  int
}

type TestResult struct {
	TestName           string
	MITRE              string
	Passed             bool
	FailReason         string
	DetectionLatencyMs int64
	ResponseAction     string
}

var mitreRegexp = regexp.MustCompile(`T\d{4}(?:\.\d{3})?`)

func runValidationSuite(ctx context.Context, a *agent.Agent, cfg *config.Config) int {
	fmt.Println("=== EDR Validation Suite ===")
	fmt.Printf("Version: %s\n\n", Version)
	tests := buildValidationTests()
	results := make([]TestResult, 0, len(tests))
	passed, failed := 0, 0
	agentCtx, agentCancel := context.WithCancel(ctx)
	defer agentCancel()
	go func() { _ = a.Run(agentCtx) }()
	time.Sleep(3 * time.Second)
	for _, test := range tests {
		fmt.Printf("[ RUN ] %s (%s)\n", test.Name, test.MITRE)
		result := runOneTest(ctx, cfg, test)
		results = append(results, result)
		if result.Passed {
			passed++
			fmt.Printf("[ PASS ] %s — detected in %dms\n", test.Name, result.DetectionLatencyMs)
		} else {
			failed++
			fmt.Printf("[ FAIL ] %s — %s\n", test.Name, result.FailReason)
		}
		if test.Cleanup != nil {
			test.Cleanup()
		}
		time.Sleep(500 * time.Millisecond)
	}
	fmt.Printf("\n=== Results: %d/%d passed ===\n", passed, len(tests))
	for _, r := range results {
		status := "PASS"
		if !r.Passed {
			status = "FAIL"
		}
		fmt.Printf("  [%s] %-40s %s latency=%dms\n", status, r.TestName, r.MITRE, r.DetectionLatencyMs)
	}
	if failed > 0 {
		fmt.Printf("\n%d tests FAILED\n", failed)
		return 1
	}
	fmt.Println("\nAll tests passed")
	return 0
}

func runOneTest(ctx context.Context, cfg *config.Config, test ValidationTest) TestResult {
	res := TestResult{TestName: test.Name, MITRE: test.MITRE}
	alertPath := cfg.Logging.AlertFile
	startOffset := fileSize(alertPath)
	startAt := time.Now()
	if err := test.Simulate(ctx); err != nil {
		res.FailReason = fmt.Sprintf("simulate failed: %v", err)
		return res
	}
	timeout := time.Duration(test.TimeoutSec) * time.Second
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		select {
		case <-ctx.Done():
			res.FailReason = "context cancelled"
			return res
		default:
		}
		ds, _ := readDetectionsFromAlerts(alertPath, startOffset)
		verified := false
		if test.Verify != nil {
			verified = test.Verify(ctx, ds)
		} else {
			for _, d := range ds {
				if strings.Contains(strings.ToUpper(d.TechniqueID), strings.ToUpper(test.MITRE)) {
					verified = true
					break
				}
			}
		}
		if verified {
			res.Passed = true
			res.DetectionLatencyMs = time.Since(startAt).Milliseconds()
			return res
		}
		time.Sleep(250 * time.Millisecond)
	}
	res.FailReason = "timeout waiting for detection"
	return res
}

func readDetectionsFromAlerts(alertPath string, startOffset int64) ([]detection.Detection, error) {
	f, err := os.Open(alertPath)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	if startOffset > 0 {
		if _, err := f.Seek(startOffset, 0); err != nil {
			return nil, err
		}
	}
	sc := bufio.NewScanner(f)
	out := make([]detection.Detection, 0, 8)
	for sc.Scan() {
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 {
			continue
		}
		var al schema.Alert
		if err := json.Unmarshal(line, &al); err != nil {
			continue
		}
		txt := strings.Join([]string{al.RuleID, al.Title, al.Description}, " ")
		tech := mitreRegexp.FindString(strings.ToUpper(txt))
		out = append(out, detection.Detection{
			RuleID:      al.RuleID,
			RuleName:    al.Title,
			TechniqueID: tech,
		})
	}
	return out, nil
}

func fileSize(path string) int64 {
	st, err := os.Stat(path)
	if err != nil {
		return 0
	}
	return st.Size()
}

func buildValidationTests() []ValidationTest {
	eicarPath := filepath.Join(os.TempDir(), "eicar_test.txt")
	cronPath := filepath.Join(os.TempDir(), "edr_test_cron")
	ransomDir := filepath.Join(os.TempDir(), "edr_ransom_test")
	startupPath := getSuspiciousWritePath()
	return []ValidationTest{
		{
			Name:       "suspicious-process-spawn",
			MITRE:      "T1059",
			TimeoutSec: 10,
			Simulate: func(ctx context.Context) error {
				return buildSuspiciousCommand(ctx).Run()
			},
			Verify: func(_ context.Context, detections []detection.Detection) bool {
				for _, d := range detections {
					if strings.Contains(d.TechniqueID, "T1059") {
						return true
					}
				}
				return false
			},
		},
		{
			Name:       "suspicious-file-write",
			MITRE:      "T1547",
			TimeoutSec: 10,
			Simulate: func(_ context.Context) error {
				_ = os.MkdirAll(filepath.Dir(startupPath), 0o755)
				return os.WriteFile(startupPath, []byte("#!/bin/bash\necho owned"), 0o755)
			},
			Cleanup: func() { _ = os.Remove(startupPath) },
		},
		{
			Name:       "yara-eicar-detection",
			MITRE:      "T1204",
			TimeoutSec: 15,
			Simulate: func(_ context.Context) error {
				eicar := `X5O!P%@AP[4\PZX54(P^)7CC)7}` + `$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*`
				return os.WriteFile(eicarPath, []byte(eicar), 0o644)
			},
			Cleanup: func() { _ = os.Remove(eicarPath) },
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
		},
		{
			Name:       "process-injection-simulation",
			MITRE:      "T1055",
			TimeoutSec: 10,
			Simulate:   func(_ context.Context) error { return simulateSelfInjection() },
		},
		{
			Name:       "sensitive-file-access",
			MITRE:      "T1552",
			TimeoutSec: 10,
			Simulate:   func(_ context.Context) error { return attemptSensitiveFileRead() },
		},
		{
			Name:       "ransomware-simulation",
			MITRE:      "T1486",
			TimeoutSec: 15,
			Simulate: func(_ context.Context) error {
				_ = os.MkdirAll(ransomDir, 0o755)
				for i := range 30 {
					src := filepath.Join(ransomDir, fmt.Sprintf("file%d.txt", i))
					dst := filepath.Join(ransomDir, fmt.Sprintf("file%d.encrypted", i))
					if err := os.WriteFile(src, []byte("test"), 0o644); err != nil {
						return err
					}
					if err := os.Rename(src, dst); err != nil {
						return err
					}
				}
				return nil
			},
			Cleanup: func() { _ = os.RemoveAll(ransomDir) },
		},
		{
			Name:       "persistence-cron",
			MITRE:      "T1053",
			TimeoutSec: 10,
			Simulate: func(_ context.Context) error {
				return os.WriteFile(cronPath, []byte("* * * * * /tmp/evil.sh"), 0o644)
			},
			Cleanup: func() { _ = os.Remove(cronPath) },
		},
	}
}

func buildSuspiciousCommand(ctx context.Context) *exec.Cmd {
	if runtime.GOOS == "windows" {
		payload := base64.StdEncoding.EncodeToString([]byte("Write-Output suspicious"))
		return exec.CommandContext(ctx, "powershell.exe", "-EncodedCommand", payload)
	}
	return exec.CommandContext(ctx, "sh", "-c", "echo suspicious")
}

func getSuspiciousWritePath() string {
	home, _ := os.UserHomeDir()
	switch runtime.GOOS {
	case "windows":
		appData := os.Getenv("APPDATA")
		if appData == "" {
			appData = filepath.Join(home, "AppData", "Roaming")
		}
		return filepath.Join(appData, "Microsoft", "Windows", "Start Menu", "Programs", "Startup", "edr_test_startup.bat")
	case "darwin":
		return filepath.Join(home, "Library", "LaunchAgents", "com.razatech.edr.test.plist")
	default:
		return filepath.Join(home, ".config", "autostart", "edr_test.desktop")
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
