// Package main implements the cross-platform EDR agent installer. It handles
// binary deployment, service registration (systemd, launchd, Windows Service),
// initial configuration generation, and clean uninstallation.
package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"text/template"
	"time"

	"github.com/google/uuid"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"

	"github.com/razatechofficial/edr/internal/config"
	"github.com/razatechofficial/edr/internal/hostperm"
	"github.com/razatechofficial/edr/internal/installprogress"
	"github.com/razatechofficial/edr/internal/telemetryqueue"
	"github.com/razatechofficial/edr/internal/xdrclient"
)

var (
	version   = "dev"
	commit    = "none"
	buildDate = "unknown"
)

var (
	flagDataDir    string
	flagConfigPath string
	// Optional directory containing models/ and rules/ subfolders (defaults to the installer's directory).
	flagBundleDir string

	flagEnrollmentHost      string
	flagEnrollmentToken     string
	flagEnrollmentTokenFile string
	flagEnroll              bool
	flagDelayEnroll         bool
	flagEnrollmentInsecure  bool
	flagNoStart             bool
	flagKeepData            bool
)

func main() {
	root := &cobra.Command{
		Use:   "edr-installer",
		Short: "EDR agent installer and service manager",
		Long: `Attended (Windows/macOS): run with no arguments to open the EDR Agent setup wizard (EULA → copy files → Launch). Linux prints a terminal license prompt.

Silent fleet: edr-installer install [--enrollment-token TOKEN]
The sensor is not started in the attended wizard (--no-start). First-run enrollment happens after Launch.`,
		CompletionOptions: cobra.CompletionOptions{
			DisableDefaultCmd: true,
		},
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	root.PersistentFlags().StringVar(&flagDataDir, "data-dir", "", "override default data directory")
	root.PersistentFlags().StringVar(&flagConfigPath, "config", "", "path to agent configuration file (skips unattended enterprise config)")
	root.PersistentFlags().StringVar(&flagBundleDir, "bundle-dir", "", "directory containing models/ and rules/ to install (default: directory of this installer binary)")

	installCmd := &cobra.Command{
		Use:   "install",
		Short: "Deploy agent, bundled ML models, rules, and service (enterprise zero-touch)",
		Long: `Unattended enterprise install: copies edr-agent and edrctl, installs models/ and rules/ from the same directory as this installer (override with --bundle-dir), writes a full agent.yaml (ML enabled, air-gap safe defaults, unique agent ID), and registers the system service.

Place edr-installer in a folder alongside models/ and rules/ (see "make bundle-enterprise"), then run: sudo ./edr-installer install

XDR enrollment (token from the console Agents page; host defaults to production):
  sudo ./edr-installer install --enrollment-token "$TOKEN"

Token is written to a root-only sidecar and cleared after Register (unless --delay-enroll).
Tenant is bound server-side from the enrollment token (not an agent input).

Use --config only if you must supply a custom YAML instead of the generated enterprise profile.`,
		RunE: runInstall,
	}
	installCmd.Flags().StringVar(&flagEnrollmentHost, "enrollment-host", "", "XDR enrollment host:port")
	installCmd.Flags().StringVar(&flagEnrollmentToken, "enrollment-token", "", "XDR one-time enrollment token")
	installCmd.Flags().StringVar(&flagEnrollmentTokenFile, "enrollment-token-file", "", "read enrollment token from file")
	installCmd.Flags().BoolVar(&flagEnroll, "enroll", true, "run XDR enrollment after install when token+host are present")
	installCmd.Flags().BoolVar(&flagDelayEnroll, "delay-enroll", false, "install token sidecar only; agent enrolls on first start")
	installCmd.Flags().BoolVar(&flagEnrollmentInsecure, "enrollment-insecure", false, "insecure gRPC to enrollment (lab/dev)")
	installCmd.Flags().BoolVar(&flagNoStart, "no-start", false, "register the service but do not start the sensor (attended first-run)")

	uninstallCmd := &cobra.Command{
		Use:   "uninstall",
		Short: "Stop service and purge EDR Agent from this computer",
		Long: `Stops the sensor, unregisters the service, and removes binaries, rules, ML models,
certificates, keystore material, logs, and the offline spool.

Requires administrator / root (the OS password prompt). Use --keep-data only when
a support engineer asks to preserve forensics under the data directory.`,
		RunE: runUninstall,
	}
	uninstallCmd.Flags().BoolVar(&flagKeepData, "keep-data", false, "leave the data directory (forensics) on disk")

	versionCmd := &cobra.Command{
		Use:   "version",
		Short: "Print installer version information",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Printf("edr-installer %s\n  commit:  %s\n  built:   %s\n  go:      %s\n  os/arch: %s/%s\n",
				version, commit, buildDate, runtime.Version(), runtime.GOOS, runtime.GOARCH)
		},
	}

	wizardCmd := &cobra.Command{
		Use:   "wizard",
		Short: "Attended installer (EULA + files, then Launch)",
		RunE:  runAttendedEntry,
	}

	root.RunE = runAttendedEntry
	root.AddCommand(installCmd, uninstallCmd, versionCmd, wizardCmd)

	if err := root.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

// runInstall performs the full agent installation sequence: privilege check,
// directory creation, binary copy, config generation, and service registration.
func runInstall(cmd *cobra.Command, args []string) error {
	if err := requirePrivileged(); err != nil {
		return err
	}

	installprogress.Clear()
	installprogress.Write("reqs")

	paths := platformPaths()
	if err := requireSpoolDisk(paths.dataDir); err != nil {
		installprogress.Write("fail")
		return err
	}

	fmt.Println("==> Creating directories")
	for _, dir := range []string{
		paths.binDir, paths.configDir, paths.dataDir, paths.logDir, paths.rulesDir,
		paths.quarantineDir,
		filepath.Join(paths.dataDir, "models"),
		filepath.Join(paths.dataDir, "installer", "bin"),
		filepath.Join(paths.dataDir, "ioc"),
		filepath.Join(paths.dataDir, "alerts"),
		filepath.Join(paths.dataDir, "forensics"),
		filepath.Join(paths.dataDir, "vectordb"),
		filepath.Join(paths.dataDir, "telemetry-queue"),
	} {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return fmt.Errorf("creating directory %s: %w", dir, err)
		}
		fmt.Printf("    %s\n", dir)
	}

	installprogress.Write("pkg")

	if flagConfigPath == "" {
		bundleRoot, err := resolveBundleRoot()
		if err != nil {
			return err
		}
		if err := installBundledAssets(bundleRoot, paths); err != nil {
			return fmt.Errorf("installing bundled payload: %w", err)
		}
	}

	fmt.Println("==> Deploying agent binary")
	agentSrc, err := findAgentBinary(&paths)
	if err != nil {
		return err
	}
	agentDst := filepath.Join(paths.binDir, agentBinaryName())
	if err := copyFile(agentSrc, agentDst, 0755); err != nil {
		return fmt.Errorf("deploying agent binary: %w", err)
	}
	fmt.Printf("    %s -> %s\n", agentSrc, agentDst)

	if runtime.GOOS == "darwin" {
		if wrapped, err := wrapDarwinSensorApp(agentDst); err != nil {
			fmt.Printf("    warning: sensor app bundle: %v\n", err)
		} else {
			agentDst = wrapped
			fmt.Printf("    Full Disk Access item: /usr/local/libexec/edr-agent.app\n")
		}
	}

	edrctlSrc := findEdrctlBinary(&paths)
	if edrctlSrc != "" {
		edrctlDst := filepath.Join(paths.binDir, edrctlBinaryName())
		if err := copyFile(edrctlSrc, edrctlDst, 0755); err != nil {
			fmt.Printf("    warning: could not deploy edrctl: %v\n", err)
		} else {
			fmt.Printf("    %s -> %s\n", edrctlSrc, edrctlDst)
			aliasDst := filepath.Join(paths.binDir, edrAliasBinaryName())
			if err := copyFile(edrctlSrc, aliasDst, 0755); err != nil {
				fmt.Printf("    warning: could not deploy edr alias: %v\n", err)
			} else {
				fmt.Printf("    %s -> %s\n", edrctlSrc, aliasDst)
			}
		}
	}

	if uiSrc := findAgentUIBinary(&paths); uiSrc != "" {
		if err := deployAgentUI(uiSrc, paths); err != nil {
			fmt.Printf("    warning: could not deploy EDR Agent UI: %v\n", err)
		}
	}

	configDst := installedConfigPath(paths)
	if flagConfigPath != "" {
		fmt.Println("==> Installing provided config")
		if err := copyFile(flagConfigPath, configDst, 0644); err != nil {
			return fmt.Errorf("installing config: %w", err)
		}
	} else {
		fmt.Println("==> Generating enterprise configuration (no manual editing required)")
		if err := generateConfig(configDst, paths); err != nil {
			return fmt.Errorf("generating config: %w", err)
		}
	}
	fmt.Printf("    %s\n", configDst)

	if err := applyInstallEnrollment(configDst, paths); err != nil {
		installprogress.Write("fail")
		return err
	}

	installprogress.Write("daemon")

	fmt.Println("==> Installing platform service")
	if err := installService(paths, agentDst, configDst); err != nil {
		installprogress.Write("fail")
		return fmt.Errorf("installing service: %w", err)
	}

	fmt.Println("==> Registering login autostart (all users)")
	if err := installLoginAutostart(paths); err != nil {
		fmt.Printf("    warning: %v\n", err)
	}

	installprogress.Write("done")
	fmt.Println("==> Installation complete")
	fmt.Printf("    Agent ID: check %s\n", configDst)
	fmt.Printf("    Data dir: %s\n", paths.dataDir)
	fmt.Printf("    Logs:     %s\n", paths.logDir)
	return nil
}

// applyInstallEnrollment writes XDR bootstrap material and optionally Registers.
func applyInstallEnrollment(configDst string, paths installPaths) error {
	host := strings.TrimSpace(flagEnrollmentHost)
	token := strings.TrimSpace(flagEnrollmentToken)
	tokenFileIn := strings.TrimSpace(flagEnrollmentTokenFile)
	if token == "" && tokenFileIn == "" {
		return nil
	}
	if host == "" {
		host = xdrclient.DefaultEnrollmentHost
	}
	if token == "" && tokenFileIn != "" {
		b, err := os.ReadFile(tokenFileIn)
		if err != nil {
			return fmt.Errorf("read --enrollment-token-file: %w", err)
		}
		token = strings.TrimSpace(string(b))
	}
	if token == "" {
		return fmt.Errorf("enrollment token required (--enrollment-token or --enrollment-token-file)")
	}

	fmt.Println("==> Configuring XDR enrollment bootstrap")
	if err := xdrclient.PatchXDRConfigFile(configDst, host, flagEnrollmentInsecure); err != nil {
		return fmt.Errorf("patch xdr config: %w", err)
	}
	sidecar := xdrclient.DefaultEnrollmentTokenPath(paths.configDir)
	if err := xdrclient.WriteEnrollmentTokenFile(sidecar, token); err != nil {
		return fmt.Errorf("write enrollment token file: %w", err)
	}
	fmt.Printf("    enrollment_host: %s\n", host)
	fmt.Printf("    token_file:      %s (mode 0600)\n", sidecar)

	if flagDelayEnroll || !flagEnroll {
		fmt.Println("    delay-enroll: agent will enroll on first start")
		return nil
	}

	fmt.Println("==> Enrolling with XDR")
	cfg, err := config.Load(configDst)
	if err != nil {
		return fmt.Errorf("load config for enroll: %w", err)
	}
	boot, err := xdrclient.ApplyBootstrap(&cfg.XDR, xdrclient.BootstrapOverrides{
		Host:            host,
		Token:           token,
		TokenFile:       sidecar,
		InsecureSkipTLS: flagEnrollmentInsecure,
		InsecureSet:     true,
		ConfigDir:       paths.configDir,
		DataDir:         paths.dataDir,
	})
	if err != nil {
		return err
	}
	cfg.XDR.Enabled = true
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	res, err := xdrclient.EnsureEnrolled(ctx, xdrclient.EnrollOptions{
		Config:        cfg.XDR,
		AgentID:       cfg.Agent.ID,
		AgentVer:      firstNonEmpty(cfg.Agent.Version, version),
		DataDir:       paths.dataDir,
		Logger:        slog.Default(),
		ConfigPath:    configDst,
		TokenFileUsed: boot.TokenFileUsed,
	})
	if err != nil {
		return fmt.Errorf("xdr enroll: %w", err)
	}
	fmt.Printf("    enrolled agent_id=%s secure_storage=%s\n", res.State.AgentID, res.State.SecureStorage)
	return nil
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if s := strings.TrimSpace(v); s != "" {
			return s
		}
	}
	return ""
}

func requireSpoolDisk(dataDir string) error {
	probe := dataDir
	if _, err := os.Stat(probe); err != nil {
		probe = filepath.Dir(dataDir)
	}
	free, err := hostperm.DiskFree(probe)
	if err != nil {
		return nil
	}
	need := hostperm.MinFreeForSpool
	if free < need {
		return fmt.Errorf("need at least 2 GiB free for the offline telemetry queue (have %.1f GiB on %s)", float64(free)/float64(1<<30), probe)
	}
	fmt.Printf("    disk: %.1f GiB free (queue cap %d GiB, retain %d days)\n",
		float64(free)/float64(1<<30), telemetryqueue.DefaultMaxBytes>>30, telemetryqueue.DefaultMaxAgeDays)
	return nil
}

// runUninstall stops the agent service and removes EDR Agent from the host.
// Admin/root is required (sudo, UAC, or the OS password dialog from the UI).
func runUninstall(cmd *cobra.Command, args []string) error {
	if err := requirePrivileged(); err != nil {
		return err
	}

	paths := platformPaths()

	fmt.Println("==> Stopping service")
	if err := stopService(); err != nil {
		fmt.Printf("    warning: %v\n", err)
	}

	fmt.Println("==> Stopping leftover sensor processes")
	stopProductProcesses()

	fmt.Println("==> Removing login autostart")
	removeLoginAutostart()

	if runtime.GOOS == "darwin" {
		fmt.Println("==> Removing consumer first-run LaunchAgent (if present)")
		removeDarwinFirstRunAgent(paths)
	}

	fmt.Println("==> Removing service registration")
	if err := removeService(paths); err != nil {
		fmt.Printf("    warning: %v\n", err)
	}

	fmt.Println("==> Clearing device identity (certs, keys, keystore)")
	_ = xdrclient.ResetLocalIdentity(paths.dataDir, "auto")

	fmt.Println("==> Removing binaries")
	binNames := []string{agentBinaryName(), edrctlBinaryName(), edrAliasBinaryName(), agentUIBinaryName()}
	if runtime.GOOS == "darwin" {
		binNames = append(binNames, "edr-installer")
	}
	for _, name := range binNames {
		p := filepath.Join(paths.binDir, name)
		if err := os.Remove(p); err != nil && !os.IsNotExist(err) {
			fmt.Printf("    warning: removing %s: %v\n", p, err)
		} else if err == nil {
			fmt.Printf("    removed %s\n", p)
		}
	}
	fmt.Println("==> Removing leftover install trees")
	purgeTrees(extraPurgeTrees())

	fmt.Println("==> Removing configuration")
	for _, name := range []string{installedConfigFileName(), "agent.yaml", "config.yml", "enrollment.token", "com.razatech.edr.enrollment-token"} {
		configDst := filepath.Join(paths.configDir, name)
		if err := os.Remove(configDst); err != nil && !os.IsNotExist(err) {
			fmt.Printf("    warning: %v\n", err)
		}
	}

	if !flagKeepData {
		fmt.Println("==> Purging data (rules, models, queue, certs, alerts, forensics)")
		for _, dir := range []string{paths.dataDir, paths.logDir, paths.rulesDir, paths.quarantineDir, paths.configDir} {
			if strings.TrimSpace(dir) == "" || dir == "/" {
				continue
			}
			if err := os.RemoveAll(dir); err != nil && !os.IsNotExist(err) {
				fmt.Printf("    warning: removing %s: %v\n", dir, err)
			} else {
				fmt.Printf("    removed %s\n", dir)
			}
		}
		if runtime.GOOS == "linux" {
			_ = os.RemoveAll("/etc/edr")
			_ = os.RemoveAll("/var/lib/edr")
		}
		if runtime.GOOS == "windows" {
			_ = runCmd("netsh", "advfirewall", "firewall", "delete", "rule", "name=EDR Agent")
		}
		purgeUserConsoleState()
	} else {
		fmt.Printf("    --keep-data: left %s in place\n", paths.dataDir)
	}

	fmt.Println("==> Forgetting installer receipts")
	forgetPackageReceipts()
	removeInstanceLocks()

	fmt.Println("==> Closing the installed console")
	quitInstalledConsole()

	fmt.Println("==> Uninstallation complete")
	return nil
}

// installPaths holds resolved platform-specific directory paths.
type installPaths struct {
	binDir        string
	configDir     string
	dataDir       string
	logDir        string
	rulesDir      string
	quarantineDir string
}

func installedConfigFileName() string {
	switch runtime.GOOS {
	case "windows", "linux":
		return "config.yml"
	default:
		return "agent.yaml"
	}
}

func installedConfigPath(p installPaths) string {
	return filepath.Join(p.configDir, installedConfigFileName())
}

// platformPaths returns the canonical directory layout for the current OS,
// respecting any user overrides via --data-dir.
func platformPaths() installPaths {
	var p installPaths
	switch runtime.GOOS {
	case "linux":
		p = installPaths{
			binDir:        "/usr/local/bin",
			configDir:     "/etc/edr-agent",
			dataDir:       "/var/lib/edr-agent",
			logDir:        "/var/log/edr-agent",
			rulesDir:      "/etc/edr-agent/rules",
			quarantineDir: "/var/lib/edr-agent/quarantine",
		}
	case "darwin":
		cfg := "/Library/Application Support/EDR/config"
		p = installPaths{
			binDir:        "/usr/local/bin",
			configDir:     cfg,
			dataDir:       "/Library/Application Support/EDR",
			logDir:        "/Library/Logs/EDR",
			rulesDir:      filepath.Join(cfg, "rules"),
			quarantineDir: "/Library/Application Support/EDR/quarantine",
		}
	case "windows":
		pf := os.Getenv("ProgramFiles")
		if pf == "" {
			pf = `C:\Program Files`
		}
		pd := os.Getenv("ProgramData")
		if pd == "" {
			pd = `C:\ProgramData`
		}
		root := filepath.Join(pd, "EDR Agent")
		p = installPaths{
			binDir:        filepath.Join(pf, "EDR Agent"),
			configDir:     root,
			dataDir:       root,
			logDir:        filepath.Join(root, "logs"),
			rulesDir:      filepath.Join(root, "rules"),
			quarantineDir: filepath.Join(root, "quarantine"),
		}
	default:
		p = installPaths{
			binDir:        "/usr/local/bin",
			configDir:     "/etc/edr-agent",
			dataDir:       "/var/lib/edr-agent",
			logDir:        "/var/log/edr-agent",
			rulesDir:      "/etc/edr-agent/rules",
			quarantineDir: "/var/lib/edr-agent/quarantine",
		}
	}

	if flagDataDir != "" {
		p.dataDir = flagDataDir
		p.quarantineDir = filepath.Join(flagDataDir, "quarantine")
	}

	return p
}

// requirePrivileged returns an error if the current process does not have
// root (Unix) or administrator (Windows) privileges.
func requirePrivileged() error {
	switch runtime.GOOS {
	case "linux", "darwin":
		if os.Getuid() != 0 {
			return fmt.Errorf("this operation requires root privileges (uid=%d); re-run with sudo", os.Getuid())
		}
	case "windows":
		if !windowsIsAdmin() {
			return fmt.Errorf("this operation requires administrator privileges; re-run in an elevated prompt")
		}
	}
	return nil
}

// generateConfig creates an enterprise agent.yaml: ML on, air-gap friendly,
// unique agent ID, and paths aligned with installBundledAssets + platform layout.
func generateConfig(dst string, paths installPaths) error {
	cfg := config.Defaults()

	id := uuid.NewString()
	cfg.Agent.ID = id
	cfg.Agent.Name = hostname()
	cfg.Agent.Environment = "enterprise"
	cfg.Agent.LogLevel = "info"
	cfg.Agent.DataDir = paths.dataDir
	cfg.Agent.TempDir = filepath.Join(paths.dataDir, "tmp")

	// No control plane until you enroll — safe unattended default.
	cfg.Server.Endpoint = ""
	cfg.Server.AirGapMode = true
	cfg.Server.MutualTLS = false
	cfg.Server.GRPCPort = 50051

	cfg.LLM.Enabled = false
	cfg.LLM.RAG.Enabled = true
	cfg.LLM.RAG.VectorDBPath = filepath.Join(paths.dataDir, "vectordb")

	cfg.ML.Enabled = true
	cfg.ML.ModelsDir = filepath.Join(paths.dataDir, "models")
	cfg.ML.AutoUpdate = false
	cfg.ML.UpdateIntervalH = 0
	cfg.ML.VerifyPubKey = ""
	cfg.ML.Models.PEClassifier = "pe_classifier.onnx"
	cfg.ML.Models.BehaviorLSTM = "behavior_lstm.onnx"
	cfg.ML.Models.NetworkAnomaly = "network_anomaly.onnx"
	cfg.ML.Models.Ransomware = "ransomware.onnx"
	cfg.ML.Models.NetworkLGBM = "network_lgbm.onnx"
	cfg.ML.Models.RATC2 = "rat_c2_detector.onnx"

	cfg.Detection.Sigma.Enabled = true
	cfg.Detection.Sigma.RulesDir = filepath.Join(paths.rulesDir, "sigma")
	cfg.Detection.YARA.Enabled = true
	cfg.Detection.YARA.RulesDir = filepath.Join(paths.rulesDir, "yara")
	cfg.Detection.CustomRules.Enabled = true
	cfg.Detection.CustomRules.RulesPath = filepath.Join(paths.rulesDir, "custom")
	cfg.Detection.IOC.Enabled = true
	cfg.Detection.IOC.HashDBPath = filepath.Join(paths.dataDir, "ioc", "hashes.db")
	cfg.Detection.IOC.IPDBPath = filepath.Join(paths.dataDir, "ioc", "ips.db")
	cfg.Detection.IOC.DomainDBPath = filepath.Join(paths.dataDir, "ioc", "domains.db")
	cfg.Detection.Behavioral.SensitivityLevel = "high"
	cfg.Detection.Behavioral.RansomwareDetect = true
	cfg.Detection.Behavioral.RATDetect = true
	cfg.Detection.Behavioral.ExfilDetect = true
	cfg.Detection.Behavioral.LateralDetect = true

	cfg.Compliance.Enabled = true
	cfg.Compliance.RulesDir = filepath.Join(paths.rulesDir, "compliance", "sca")
	cfg.Monitoring.KernelEnabled = true
	cfg.Monitoring.LinuxRootcheckEnabled = true

	cfg.Response.Quarantine.Dir = paths.quarantineDir
	cfg.Response.Forensics.OutputDir = filepath.Join(paths.dataDir, "forensics")

	cfg.Logging.Level = "info"
	cfg.Logging.AlertFile = filepath.Join(paths.logDir, "alerts.jsonl")
	cfg.Logging.AuditFile = filepath.Join(paths.logDir, "audit.jsonl")

	cfg.Response.AutoResponse = true
	cfg.Response.Actions.KillProcess = true
	cfg.LegacyResponse.AllowKill = true
	cfg.LegacyResponse.AutoKillEnabled = true

	cfg.Service.EndpointID = id
	cfg.Service.TickInterval = time.Second
	cfg.Service.PIDFile = filepath.Join(paths.dataDir, "agent.pid")

	// Absolute path: matches installBundledAssets (rules copied to paths.rulesDir).
	cfg.RulesFile = filepath.Join(paths.rulesDir, "baseline.yaml")

	cfg.SelfProtect.Enabled = true
	cfg.SelfProtect.Watchdog = true
	cfg.SelfProtect.IntegrityCheck = true

	cfg.XDR.Enabled = false
	cfg.XDR.EnrollmentHost = xdrclient.DefaultEnrollmentHost
	cfg.XDR.IngestHosts = xdrclient.DefaultIngestHosts()
	cfg.XDR.InsecureSkipTLS = false
	cfg.XDR.SecureStorage = "auto"
	cfg.XDR.CertDir = filepath.Join(paths.dataDir, "xdr-tls")
	cfg.XDR.RenewBeforeDays = 7

	data, err := yaml.Marshal(cfg)
	if err != nil {
		return fmt.Errorf("marshaling config: %w", err)
	}
	return os.WriteFile(dst, data, 0644)
}

// resolveBundleRoot returns the directory that contains models/ and rules/ (typically the installer's directory).
func resolveBundleRoot() (string, error) {
	if flagBundleDir != "" {
		abs, err := filepath.Abs(flagBundleDir)
		if err != nil {
			return "", err
		}
		st, err := os.Stat(abs)
		if err != nil || !st.IsDir() {
			return "", fmt.Errorf("bundle-dir is not a directory: %s", flagBundleDir)
		}
		return abs, nil
	}
	exe, err := os.Executable()
	if err != nil {
		return "", fmt.Errorf("resolve installer path: %w", err)
	}
	exe, err = filepath.EvalSymlinks(exe)
	if err != nil {
		return "", err
	}
	return filepath.Dir(exe), nil
}

// installBundledAssets copies models/ and rules/ from the bundle (release folder) into system paths.
func installBundledAssets(bundleRoot string, paths installPaths) error {
	fmt.Println("==> Installing bundled assets (enterprise zero-touch)")
	if em := embeddedAssets(); em != nil {
		fmt.Println("    source: embedded in this binary (build: -tags embedbundle)")
		if err := extractEmbeddedInstallerAssets(em, paths); err != nil {
			return err
		}
		fmt.Printf("    models -> %s\n", filepath.Join(paths.dataDir, "models"))
		fmt.Printf("    rules  -> %s\n", paths.rulesDir)
		return nil
	}

	modelsSrc := filepath.Join(bundleRoot, "models")
	if st, err := os.Stat(modelsSrc); err == nil && st.IsDir() {
		dst := filepath.Join(paths.dataDir, "models")
		if err := copyDir(modelsSrc, dst); err != nil {
			return fmt.Errorf("copy models: %w", err)
		}
		fmt.Printf("    models: %s -> %s\n", modelsSrc, dst)
	} else {
		fmt.Fprintf(os.Stderr, "    warning: %s not found — ship a models/ folder next to edr-installer for bundled ML.\n", modelsSrc)
	}

	rulesSrc := filepath.Join(bundleRoot, "rules")
	if st, err := os.Stat(rulesSrc); err == nil && st.IsDir() {
		if err := copyDir(rulesSrc, paths.rulesDir); err != nil {
			return fmt.Errorf("copy rules: %w", err)
		}
		fmt.Printf("    rules:  %s -> %s\n", rulesSrc, paths.rulesDir)
	} else {
		fmt.Fprintf(os.Stderr, "    warning: %s not found — ship rules/ next to edr-installer for detection rules.\n", rulesSrc)
	}
	return nil
}

func copyDir(src, dst string) error {
	return filepath.Walk(src, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}
		out := filepath.Join(dst, rel)
		if info.IsDir() {
			if rel == "." {
				return os.MkdirAll(out, 0755)
			}
			return os.MkdirAll(out, 0755)
		}
		if err := os.MkdirAll(filepath.Dir(out), 0755); err != nil {
			return err
		}
		perm := info.Mode().Perm()
		if perm == 0 {
			perm = 0644
		}
		return copyFile(path, out, perm)
	})
}

// installService registers and starts the platform-appropriate service
// (systemd, launchd, or Windows Service).
func installService(paths installPaths, agentBin, configPath string) error {
	switch runtime.GOOS {
	case "linux":
		return installSystemd(agentBin, configPath, paths)
	case "darwin":
		return installLaunchDaemon(agentBin, configPath)
	case "windows":
		return installWindowsService(agentBin, configPath)
	default:
		return fmt.Errorf("unsupported platform: %s", runtime.GOOS)
	}
}

const darwinAgentLaunchdPlist = "/Library/LaunchDaemons/com.razatech.edr-agent.plist"

// darwinLaunchctlPath resolves launchctl. Some macOS versions only ship /bin/launchctl;
// a hard-coded /usr/bin/launchctl breaks fork/exec with "no such file or directory".
func darwinLaunchctlPath() (string, error) {
	candidates := []string{
		"/bin/launchctl",
		"/usr/bin/launchctl",
	}
	for _, p := range candidates {
		if fi, err := os.Stat(p); err == nil && !fi.IsDir() {
			return p, nil
		}
	}
	if p, err := exec.LookPath("launchctl"); err == nil {
		return p, nil
	}
	return "", fmt.Errorf("launchctl not found (checked /bin, /usr/bin, and PATH)")
}

// stopService halts the currently running EDR agent service.
func stopService() error {
	switch runtime.GOOS {
	case "linux":
		return runCmd("systemctl", "stop", "edr-agent")
	case "darwin":
		// Best-effort: if launchctl cannot be resolved, plist removal still works.
		if lc, err := darwinLaunchctlPath(); err == nil {
			_ = exec.Command(lc, "bootout", "system", darwinAgentLaunchdPlist).Run()
			_ = exec.Command(lc, "unload", darwinAgentLaunchdPlist).Run()
		}
		return nil
	case "windows":
		return stopWindowsService()
	default:
		return fmt.Errorf("unsupported platform: %s", runtime.GOOS)
	}
}

// removeDarwinFirstRunAgent unloads the consumer-package first-run job (LaunchAgent),
// removes its plist, and removes the bundled first-run script. Safe to call if
// the consumer .pkg was never installed.
func removeDarwinFirstRunAgent(paths installPaths) {
	if runtime.GOOS != "darwin" {
		return
	}
	plist := "/Library/LaunchAgents/com.razatech.edr.firstrun.plist"
	if out, err := exec.Command("stat", "-f", "%Su", "/dev/console").Output(); err == nil {
		user := strings.TrimSpace(string(out))
		if user != "" && user != "root" && user != "loginwindow" {
			if uidOut, err := exec.Command("id", "-u", user).Output(); err == nil {
				uid := strings.TrimSpace(string(uidOut))
				if uid != "" {
					target := fmt.Sprintf("gui/%s/com.razatech.edr.firstrun", uid)
					if lc, err := darwinLaunchctlPath(); err == nil {
						_ = exec.Command(lc, "bootout", target).Run()
					}
				}
			}
		}
	}
	if err := os.Remove(plist); err != nil && !os.IsNotExist(err) {
		fmt.Printf("    warning: removing %s: %v\n", plist, err)
	} else if err == nil {
		fmt.Printf("    removed %s\n", plist)
	}
	script := filepath.Join(paths.dataDir, "first-run-permissions.sh")
	if err := os.Remove(script); err != nil && !os.IsNotExist(err) {
		fmt.Printf("    warning: removing %s: %v\n", script, err)
	} else if err == nil {
		fmt.Printf("    removed %s\n", script)
	}
}

// removeService unregisters the platform service definition files.
func removeService(paths installPaths) error {
	switch runtime.GOOS {
	case "linux":
		_ = runCmd("systemctl", "disable", "edr-agent")
		return os.Remove("/etc/systemd/system/edr-agent.service")
	case "darwin":
		if lc, err := darwinLaunchctlPath(); err == nil {
			_ = exec.Command(lc, "bootout", "system", darwinAgentLaunchdPlist).Run()
		}
		return os.Remove(darwinAgentLaunchdPlist)
	case "windows":
		return removeWindowsService()
	default:
		return nil
	}
}

const systemdUnit = `[Unit]
Description=EDR Endpoint Detection and Response Agent
After=network-online.target
Wants=network-online.target
Documentation=https://github.com/razatechofficial/edr

# eBPF object must exist at /var/lib/edr/bpf/edr.bpf.o for kernel telemetry (see docs/FIRST_LAUNCH_PERMISSIONS.md).

[Service]
Type=simple
ExecStart={{.AgentBin}} run --config {{.ConfigPath}}
Restart=always
RestartSec=5
LimitNOFILE=65536
LimitMEMLOCK=infinity
WorkingDirectory={{.DataDir}}
StandardOutput=journal
StandardError=journal
SyslogIdentifier=edr-agent

# Hardening
ProtectSystem=strict
ReadWritePaths={{.DataDir}} {{.LogDir}} {{.ConfigDir}}
PrivateTmp=true
NoNewPrivileges=false
ProtectKernelModules=false
ProtectKernelTunables=false
CapabilityBoundingSet=CAP_SYS_PTRACE CAP_NET_ADMIN CAP_NET_RAW CAP_SYS_ADMIN CAP_DAC_READ_SEARCH CAP_KILL
AmbientCapabilities=CAP_SYS_PTRACE CAP_NET_ADMIN CAP_NET_RAW CAP_SYS_ADMIN CAP_DAC_READ_SEARCH CAP_KILL

[Install]
WantedBy=multi-user.target
`

// installSystemd writes a systemd service unit, reloads the daemon, and
// enables+starts the service.
func installSystemd(agentBin, configPath string, paths installPaths) error {
	tmpl, err := template.New("systemd").Parse(systemdUnit)
	if err != nil {
		return fmt.Errorf("parsing systemd template: %w", err)
	}

	unitPath := "/etc/systemd/system/edr-agent.service"
	f, err := os.OpenFile(unitPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil {
		return fmt.Errorf("creating unit file: %w", err)
	}
	defer f.Close()

	data := struct {
		AgentBin   string
		ConfigPath string
		DataDir    string
		LogDir     string
		ConfigDir  string
	}{
		AgentBin:   agentBin,
		ConfigPath: configPath,
		DataDir:    paths.dataDir,
		LogDir:     paths.logDir,
		ConfigDir:  paths.configDir,
	}
	if err := tmpl.Execute(f, data); err != nil {
		return fmt.Errorf("writing unit file: %w", err)
	}

	fmt.Printf("    created %s\n", unitPath)

	if err := runCmd("systemctl", "daemon-reload"); err != nil {
		return fmt.Errorf("systemctl daemon-reload: %w", err)
	}
	if err := runCmd("systemctl", "enable", "edr-agent"); err != nil {
		return fmt.Errorf("systemctl enable: %w", err)
	}
	if flagNoStart {
		fmt.Println("    service enabled (not started; --no-start)")
		return nil
	}
	if err := runCmd("systemctl", "start", "edr-agent"); err != nil {
		return fmt.Errorf("systemctl start: %w", err)
	}
	fmt.Println("    service enabled and started")
	return nil
}

const launchdPlist = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.razatech.edr-agent</string>
    <key>ProgramArguments</key>
    <array>
        <string>{{.AgentBin}}</string>
        <string>run</string>
        <string>--config</string>
        <string>{{.ConfigPath}}</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <dict>
        <key>Crashed</key>
        <true/>
        <key>SuccessfulExit</key>
        <false/>
    </dict>
    <key>ThrottleInterval</key>
    <integer>10</integer>
    <key>StandardOutPath</key>
    <string>/Library/Logs/EDR/agent.stdout.log</string>
    <key>StandardErrorPath</key>
    <string>/Library/Logs/EDR/agent.stderr.log</string>
</dict>
</plist>
`

// installLaunchDaemon writes a launchd plist and loads the daemon.
func installLaunchDaemon(agentBin, configPath string) error {
	tmpl, err := template.New("plist").Parse(launchdPlist)
	if err != nil {
		return fmt.Errorf("parsing plist template: %w", err)
	}

	plistPath := darwinAgentLaunchdPlist
	f, err := os.OpenFile(plistPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil {
		return fmt.Errorf("creating plist: %w", err)
	}
	defer f.Close()

	data := struct {
		AgentBin   string
		ConfigPath string
	}{
		AgentBin:   agentBin,
		ConfigPath: configPath,
	}
	if err := tmpl.Execute(f, data); err != nil {
		return fmt.Errorf("writing plist: %w", err)
	}

	fmt.Printf("    created %s\n", plistPath)

	// LaunchDaemons must be root:wheel (not root:staff) or launchctl bootstrap rejects them.
	// Use absolute paths: pkg postinstall often runs with a minimal PATH (no /usr/sbin).
	if err := runCmd("/usr/sbin/chown", "root:wheel", plistPath); err != nil {
		return fmt.Errorf("chown launchd plist: %w", err)
	}
	if err := runCmd("/bin/chmod", "644", plistPath); err != nil {
		return fmt.Errorf("chmod launchd plist: %w", err)
	}

	lc, err := darwinLaunchctlPath()
	if err != nil {
		return err
	}

	// Remove prior registration if present (upgrade / retry).
	_ = exec.Command(lc, "bootout", "system", plistPath).Run()

	if flagNoStart {
		fmt.Println("    LaunchDaemon written for next boot (RunAtLoad); not loaded now (--no-start)")
		return nil
	}

	// Prefer bootstrap; fall back to deprecated load if needed.
	if err := runCmd(lc, "bootstrap", "system", plistPath); err != nil {
		if err2 := runCmd(lc, "load", plistPath); err2 != nil {
			return fmt.Errorf("launchctl bootstrap system: %w (fallback load: %v)", err, err2)
		}
		fmt.Println("    daemon registered (launchctl load fallback)")
		return nil
	}
	fmt.Println("    daemon registered (launchctl bootstrap system)")
	return nil
}


// agentBinaryName returns the platform-specific agent binary name.
func agentBinaryName() string {
	if runtime.GOOS == "windows" {
		return "edr-agent.exe"
	}
	return "edr-agent"
}

// edrctlBinaryName returns the platform-specific CLI binary name.
func edrctlBinaryName() string {
	if runtime.GOOS == "windows" {
		return "edrctl.exe"
	}
	return "edrctl"
}

func edrAliasBinaryName() string {
	if runtime.GOOS == "windows" {
		return "edr.exe"
	}
	return "edr"
}

// findAgentBinary locates the agent binary: embedded staging (single-file installer),
// then paths next to this installer, then dev build outputs.
func findAgentBinary(paths *installPaths) (string, error) {
	suffix := fmt.Sprintf("-%s-%s", runtime.GOOS, runtime.GOARCH)
	if runtime.GOOS == "windows" {
		suffix += ".exe"
	}

	if paths != nil {
		staged := filepath.Join(paths.dataDir, "installer", "bin", agentBinaryName())
		if info, err := os.Stat(staged); err == nil && !info.IsDir() {
			abs, err := filepath.Abs(staged)
			if err != nil {
				return "", err
			}
			return abs, nil
		}
	}

	candidates := []string{
		filepath.Join("bin", "edr-agent"+suffix),
		filepath.Join(".", agentBinaryName()),
		agentBinaryName(),
	}
	if exe, err := os.Executable(); err == nil {
		if exe, err = filepath.EvalSymlinks(exe); err == nil {
			exeDir := filepath.Dir(exe)
			candidates = append([]string{
				filepath.Join(exeDir, "edr-agent"+suffix),
				filepath.Join(exeDir, agentBinaryName()),
				filepath.Join(exeDir, "bin", "edr-agent"+suffix),
			}, candidates...)
		}
	}

	for _, c := range candidates {
		if info, err := os.Stat(c); err == nil && !info.IsDir() {
			abs, _ := filepath.Abs(c)
			return abs, nil
		}
	}
	return "", fmt.Errorf("agent binary not found; tried: %s", strings.Join(candidates, ", "))
}

// findEdrctlBinary locates the edrctl binary (optional).
func findEdrctlBinary(paths *installPaths) string {
	suffix := fmt.Sprintf("-%s-%s", runtime.GOOS, runtime.GOARCH)
	if runtime.GOOS == "windows" {
		suffix += ".exe"
	}

	if paths != nil {
		staged := filepath.Join(paths.dataDir, "installer", "bin", edrctlBinaryName())
		if info, err := os.Stat(staged); err == nil && !info.IsDir() {
			abs, _ := filepath.Abs(staged)
			return abs
		}
	}

	candidates := []string{
		filepath.Join("bin", "edrctl"+suffix),
		filepath.Join(".", edrctlBinaryName()),
	}
	if exe, err := os.Executable(); err == nil {
		if exe, err = filepath.EvalSymlinks(exe); err == nil {
			exeDir := filepath.Dir(exe)
			candidates = append([]string{
				filepath.Join(exeDir, "edrctl"+suffix),
				filepath.Join(exeDir, edrctlBinaryName()),
			}, candidates...)
		}
	}

	for _, c := range candidates {
		if info, err := os.Stat(c); err == nil && !info.IsDir() {
			abs, _ := filepath.Abs(c)
			return abs
		}
	}
	return ""
}

// copyFile reads src and writes it to dst with the given permissions.
func copyFile(src, dst string, perm os.FileMode) error {
	data, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	return os.WriteFile(dst, data, perm)
}

// hostname returns the system hostname or "unknown" on failure.
func hostname() string {
	h, err := os.Hostname()
	if err != nil {
		return "unknown"
	}
	return h
}

// runCmd executes a command and returns any error.
func runCmd(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	hideConsole(cmd)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}
