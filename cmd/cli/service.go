package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/razatechofficial/edr/internal/config"
	"github.com/razatechofficial/edr/internal/platform"
	"github.com/razatechofficial/edr/internal/xdrclient"
)

func newStartCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "start",
		Short: "Start the EDR agent service (requires administrator/root)",
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := requirePrivileged(); err != nil {
				return err
			}
			return controlAgentService("start")
		},
	}
}

func newStageIdentityCmd() *cobra.Command {
	return &cobra.Command{
		Use:    "stage-identity",
		Short:  "Copy device identity from this user's keystore for the sensor",
		Hidden: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return xdrclient.StageIdentityFromLocalKeystore(config.XDRConfig{SecureStorage: "auto"}, platform.DataDir())
		},
	}
}

func newStopCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "stop",
		Short: "Stop the EDR agent service (requires administrator/root)",
		Long:  "Stopping the sensor requires administrator or root credentials (same pattern as CrowdStrike/SentinelOne/Defender).",
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := requirePrivileged(); err != nil {
				return err
			}
			return controlAgentService("stop")
		},
	}
}

func newResetIdentityCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "reset-identity",
		Short: "Remove local enrollment so a new token can register this device",
		Long:  "Stops the sensor and deletes the device certificate, key, and agent_id. Rules and config stay. Enroll again with a new one-time token.",
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := requirePrivileged(); err != nil {
				return err
			}
			_ = controlAgentService("stop")
			if runtime.GOOS == "darwin" {
				_ = exec.Command("/usr/bin/killall", "-9", "edr-agent").Run()
			}
			cfg, err := config.Load(configFile)
			if err != nil {
				return fmt.Errorf("load config %s: %w", configFile, err)
			}
			if err := xdrclient.ResetLocalIdentity(cfg.Agent.DataDir, cfg.XDR.SecureStorage); err != nil {
				return err
			}
			clearUserLoginIdentity()
			fmt.Println("local identity removed; enroll with a new one-time token")
			return nil
		},
	}
}

func clearUserLoginIdentity() {
	if runtime.GOOS != "darwin" {
		return
	}
	out, err := exec.Command("/usr/bin/stat", "-f", "%Su", "/dev/console").Output()
	if err != nil {
		return
	}
	user := strings.TrimSpace(string(out))
	if user == "" || user == "root" {
		return
	}
	for i := 0; i < 8; i++ {
		if exec.Command("/usr/bin/sudo", "-u", user, "/usr/bin/security", "delete-generic-password", "-s", "com.razatech.edr.xdr-identity").Run() != nil {
			break
		}
	}
}

func controlAgentService(action string) error {
	switch runtime.GOOS {
	case "windows":
		cmd := exec.Command("sc.exe", action, "EDRAgent")
		hideConsole(cmd)
		out, err := cmd.CombinedOutput()
		if err != nil {
			return fmt.Errorf("%s service: %w (%s)", action, err, strings.TrimSpace(string(out)))
		}
		fmt.Printf("EDRAgent %s requested\n", action)
		return nil
	case "linux":
		out, err := exec.Command("systemctl", action, "edr-agent").CombinedOutput()
		if err != nil {
			return fmt.Errorf("systemctl %s edr-agent: %w (%s)", action, err, strings.TrimSpace(string(out)))
		}
		fmt.Printf("edr-agent %s requested\n", action)
		return nil
	case "darwin":
		const (
			label = "system/com.razatech.edr-agent"
			plist = "/Library/LaunchDaemons/com.razatech.edr-agent.plist"
		)
		if action == "stop" {
			out, err := exec.Command("launchctl", "bootout", label).CombinedOutput()
			if err != nil {
				return fmt.Errorf("launchctl stop: %w (%s)", err, strings.TrimSpace(string(out)))
			}
			fmt.Printf("com.razatech.edr-agent stop requested\n")
			return nil
		}
		cfg, err := config.Load(configFile)
		if err != nil {
			return err
		}
		fileStore := xdrclient.Store{
			Dir:     xdrclient.ResolveCertDir(cfg.XDR, cfg.Agent.DataDir),
			DataDir: cfg.Agent.DataDir,
			Backend: "file",
		}
		if err := xdrclient.InstallStagedIdentity(configFile, cfg.XDR, cfg.Agent.DataDir); err != nil {
			if !fileStore.HasCredentials() {
				if rerr := rebindXDRIdentity(); rerr != nil {
					return fmt.Errorf("sensor cannot read the device certificate (%v)", err)
				}
			}
		}
		st, _ := fileStore.Load()
		restoreCAChainIfEmpty(fileStore)
		if err := xdrclient.EnableIngestFromEnrollment(configFile, st); err != nil {
			return fmt.Errorf("enable ingest: %w", err)
		}
		_ = exec.Command("launchctl", "bootout", label).Run()
		_ = exec.Command("/usr/bin/killall", "-9", "edr-agent").Run()
		time.Sleep(400 * time.Millisecond)
		dst, err := installLocalSensorBinary()
		if err != nil {
			return err
		}
		if err := pointLaunchDaemonAt(dst, plist); err != nil {
			return err
		}
		_ = exec.Command("launchctl", "bootstrap", "system", plist).Run()
		out, err := exec.Command("launchctl", "kickstart", "-k", label).CombinedOutput()
		if err != nil {
			return fmt.Errorf("launchctl start: %w (%s)", err, strings.TrimSpace(string(out)))
		}
		if err := waitAgentRunning(20 * time.Second); err != nil {
			return err
		}
		publishIngestExcerpt(cfg.Agent.DataDir)
		fmt.Printf("com.razatech.edr-agent start requested\n")
		return nil
	default:
		return fmt.Errorf("service control is not supported on %s", runtime.GOOS)
	}
}

func restoreCAChainIfEmpty(store xdrclient.Store) {
	ca := store.CAPath()
	if st, err := os.Stat(ca); err == nil && st.Size() > 0 {
		return
	}
	ing := filepath.Join(store.Dir, "ingest-ca.pem")
	b, err := os.ReadFile(ing)
	if err != nil || len(b) == 0 {
		return
	}
	_ = os.WriteFile(ca, b, 0o600)
}

func rebindXDRIdentity() error {
	cfg, err := config.Load(configFile)
	if err != nil {
		return err
	}
	store := xdrclient.Store{
		Dir:     xdrclient.ResolveCertDir(cfg.XDR, cfg.Agent.DataDir),
		DataDir: cfg.Agent.DataDir,
		Backend: cfg.XDR.SecureStorage,
	}
	st, err := store.Load()
	if err != nil {
		return err
	}
	return store.RebindDaemonReadable(st)
}

func waitAgentRunning(d time.Duration) error {
	deadline := time.Now().Add(d)
	var last string
	for time.Now().Before(deadline) {
		last = serviceRuntimeStatus()
		if last == "running" {
			return nil
		}
		time.Sleep(400 * time.Millisecond)
	}
	return fmt.Errorf("sensor did not stay running (status %s). Check /Library/Logs/EDR/stderr.log", last)
}

func serviceRuntimeStatus() string {
	switch runtime.GOOS {
	case "windows":
		return windowsServiceRuntimeStatus()
	case "linux":
		out, err := exec.Command("systemctl", "is-active", "edr-agent").CombinedOutput()
		if err != nil {
			return strings.TrimSpace(string(out))
		}
		return strings.TrimSpace(string(out))
	case "darwin":
		out, err := exec.Command("launchctl", "print", "system/com.razatech.edr-agent").CombinedOutput()
		if err != nil {
			return "not loaded"
		}
		return parseLaunchctlState(string(out))
	default:
		return "unknown"
	}
}

var (
	launchctlRunning    = regexp.MustCompile(`(?m)^\tstate = running\s*$`)
	launchctlNotRunning = regexp.MustCompile(`(?m)^\tstate = not running\s*$`)
)

func parseLaunchctlState(out string) string {
	switch {
	case launchctlRunning.MatchString(out):
		return "running"
	case launchctlNotRunning.MatchString(out):
		return "not running"
	default:
		return "loaded"
	}
}

func siblingTool(name string) string {
	exe, err := os.Executable()
	if err != nil {
		return ""
	}
	p := filepath.Join(filepath.Dir(exe), name)
	st, err := os.Stat(p)
	if err != nil || st.IsDir() {
		return ""
	}
	return p
}

func sensorBinaryCandidates() []string {
	var out []string
	if s := siblingTool("edr-agent"); s != "" {
		out = append(out, s)
	}
	out = append(out,
		"/usr/local/libexec/edr-agent.app/Contents/MacOS/edr-agent",
		"/Library/Application Support/EDR/bin/edr-agent",
		"/usr/local/bin/edr-agent",
	)
	return out
}

func resolveSensorBinary() (string, error) {
	for _, p := range sensorBinaryCandidates() {
		if st, err := os.Stat(p); err == nil && !st.IsDir() {
			return p, nil
		}
	}
	return "", fmt.Errorf("local sensor binary not found (expected edr-agent in /usr/local/bin or Application Support)")
}

func isSiblingOfSelf(p string) bool {
	exe, err := os.Executable()
	if err != nil {
		return false
	}
	return filepath.Clean(filepath.Dir(p)) == filepath.Clean(filepath.Dir(exe))
}

func installLocalSensorBinary() (string, error) {
	src, err := resolveSensorBinary()
	if err != nil {
		return "", err
	}
	// Attended Setup already copied the sensor to a system path. Use it.
	// Only copy when this is a loose zip (edr-agent next to edrctl).
	if !isSiblingOfSelf(src) {
		return src, nil
	}
	// Do not write into the signed .app — macOS and self-protect deny that (EPERM).
	dst := "/Library/Application Support/EDR/bin/edr-agent"
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return "", fmt.Errorf("sensor install path: %w", err)
	}
	raw, err := os.ReadFile(src)
	if err != nil {
		return "", fmt.Errorf("read sensor: %w", err)
	}
	tmp := dst + ".new"
	if err := os.WriteFile(tmp, raw, 0o755); err != nil {
		return "", fmt.Errorf("write sensor: %w", err)
	}
	if err := os.Rename(tmp, dst); err != nil {
		_ = os.Remove(tmp)
		return "", fmt.Errorf("replace sensor: %w", err)
	}
	_ = os.Chmod(dst, 0o755)
	_ = exec.Command("/usr/bin/xattr", "-cr", dst).Run()
	_ = exec.Command("/usr/bin/install_name_tool", "-change",
		"/usr/local/opt/yara/lib/libyara.10.dylib",
		"/usr/local/libexec/edr-agent.app/Contents/Frameworks/libyara.10.dylib",
		dst).Run()
	_ = exec.Command("/usr/bin/codesign", "--force", "--sign", "-", dst).Run()
	if _, err := os.Stat(dst); err != nil {
		return "", fmt.Errorf("sensor binary missing after install: %w", err)
	}
	return dst, nil
}

func pointLaunchDaemonAt(exe, plist string) error {
	exe = strings.TrimSpace(exe)
	if exe == "" || plist == "" {
		return fmt.Errorf("retarget service: missing path")
	}
	out, err := exec.Command("/usr/libexec/PlistBuddy", "-c", "Set :ProgramArguments:0 "+exe, plist).CombinedOutput()
	if err != nil {
		return fmt.Errorf("retarget service: %w (%s)", err, strings.TrimSpace(string(out)))
	}
	return nil
}

func publishIngestExcerpt(dataDir string) {
	dataDir = strings.TrimSpace(dataDir)
	if dataDir == "" {
		return
	}
	src := filepath.Join(dataDir, "logs", "agent.log")
	out, err := exec.Command("/usr/bin/tail", "-c", "524288", src).Output()
	if err != nil || len(out) == 0 {
		return
	}
	var keep []string
	for _, line := range strings.Split(string(out), "\n") {
		l := strings.ToLower(line)
		if strings.Contains(l, "ingest") || strings.Contains(l, "xdr enroll") ||
			strings.Contains(l, "credentials loaded") || strings.Contains(l, "telemetry relay") {
			if len(line) > 500 {
				line = line[:500]
			}
			keep = append(keep, line)
		}
	}
	if len(keep) > 40 {
		keep = keep[len(keep)-40:]
	}
	_ = os.WriteFile("/Library/Logs/EDR/ingest-last.log", []byte(strings.Join(keep, "\n")+"\n"), 0o644)
}
