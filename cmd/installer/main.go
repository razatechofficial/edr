// Package main implements the cross-platform EDR agent installer. It handles
// binary deployment, service registration (systemd, launchd, Windows Service),
// initial configuration generation, and clean uninstallation.
package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"text/template"

	"github.com/google/uuid"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"

	"github.com/razatechofficial/edr/internal/config"
)

var (
	version   = "dev"
	commit    = "none"
	buildDate = "unknown"
)

var (
	flagDataDir    string
	flagConfigPath string
)

func main() {
	root := &cobra.Command{
		Use:   "edr-installer",
		Short: "EDR agent installer and service manager",
		Long:  "Cross-platform installer that deploys the EDR agent binary, generates initial configuration, creates data directories, and registers the platform service.",
		CompletionOptions: cobra.CompletionOptions{
			DisableDefaultCmd: true,
		},
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	root.PersistentFlags().StringVar(&flagDataDir, "data-dir", "", "override default data directory")
	root.PersistentFlags().StringVar(&flagConfigPath, "config", "", "path to agent configuration file")

	installCmd := &cobra.Command{
		Use:   "install",
		Short: "Deploy agent binary, config, and register platform service",
		Long:  "Copies the agent binary to the system path, creates data directories, generates an initial config with a unique agent ID, and installs/starts the platform service (systemd on Linux, launchd on macOS, Windows Service on Windows).",
		RunE:  runInstall,
	}

	uninstallCmd := &cobra.Command{
		Use:   "uninstall",
		Short: "Stop service, remove files, and unregister the agent",
		Long:  "Stops the running EDR agent service, removes installed binaries, configuration, data directories, and unregisters the platform service.",
		RunE:  runUninstall,
	}

	versionCmd := &cobra.Command{
		Use:   "version",
		Short: "Print installer version information",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Printf("edr-installer %s\n  commit:  %s\n  built:   %s\n  go:      %s\n  os/arch: %s/%s\n",
				version, commit, buildDate, runtime.Version(), runtime.GOOS, runtime.GOARCH)
		},
	}

	root.AddCommand(installCmd, uninstallCmd, versionCmd)

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

	paths := platformPaths()

	fmt.Println("==> Creating directories")
	for _, dir := range []string{paths.binDir, paths.configDir, paths.dataDir, paths.logDir, paths.rulesDir, paths.quarantineDir} {
		if err := os.MkdirAll(dir, 0750); err != nil {
			return fmt.Errorf("creating directory %s: %w", dir, err)
		}
		fmt.Printf("    %s\n", dir)
	}

	fmt.Println("==> Deploying agent binary")
	agentSrc, err := findAgentBinary()
	if err != nil {
		return err
	}
	agentDst := filepath.Join(paths.binDir, agentBinaryName())
	if err := copyFile(agentSrc, agentDst, 0755); err != nil {
		return fmt.Errorf("deploying agent binary: %w", err)
	}
	fmt.Printf("    %s -> %s\n", agentSrc, agentDst)

	edrctlSrc := findEdrctlBinary()
	if edrctlSrc != "" {
		edrctlDst := filepath.Join(paths.binDir, edrctlBinaryName())
		if err := copyFile(edrctlSrc, edrctlDst, 0755); err != nil {
			fmt.Printf("    warning: could not deploy edrctl: %v\n", err)
		} else {
			fmt.Printf("    %s -> %s\n", edrctlSrc, edrctlDst)
		}
	}

	configDst := filepath.Join(paths.configDir, "agent.yaml")
	if flagConfigPath != "" {
		fmt.Println("==> Installing provided config")
		if err := copyFile(flagConfigPath, configDst, 0640); err != nil {
			return fmt.Errorf("installing config: %w", err)
		}
	} else {
		fmt.Println("==> Generating initial configuration")
		if err := generateConfig(configDst, paths); err != nil {
			return fmt.Errorf("generating config: %w", err)
		}
	}
	fmt.Printf("    %s\n", configDst)

	fmt.Println("==> Installing platform service")
	if err := installService(paths, agentDst, configDst); err != nil {
		return fmt.Errorf("installing service: %w", err)
	}

	fmt.Println("==> Installation complete")
	fmt.Printf("    Agent ID: check %s\n", configDst)
	fmt.Printf("    Data dir: %s\n", paths.dataDir)
	fmt.Printf("    Logs:     %s\n", paths.logDir)
	return nil
}

// runUninstall stops the agent service, removes installed files, and
// unregisters the platform service.
func runUninstall(cmd *cobra.Command, args []string) error {
	if err := requirePrivileged(); err != nil {
		return err
	}

	paths := platformPaths()

	fmt.Println("==> Stopping service")
	if err := stopService(); err != nil {
		fmt.Printf("    warning: %v\n", err)
	}

	fmt.Println("==> Removing service registration")
	if err := removeService(paths); err != nil {
		fmt.Printf("    warning: %v\n", err)
	}

	fmt.Println("==> Removing binaries")
	for _, name := range []string{agentBinaryName(), edrctlBinaryName()} {
		p := filepath.Join(paths.binDir, name)
		if err := os.Remove(p); err != nil && !os.IsNotExist(err) {
			fmt.Printf("    warning: removing %s: %v\n", p, err)
		} else {
			fmt.Printf("    removed %s\n", p)
		}
	}

	fmt.Println("==> Removing configuration")
	configDst := filepath.Join(paths.configDir, "agent.yaml")
	if err := os.Remove(configDst); err != nil && !os.IsNotExist(err) {
		fmt.Printf("    warning: %v\n", err)
	}

	fmt.Println("==> Uninstallation complete")
	fmt.Printf("    Note: data directory %s was preserved. Remove manually if desired.\n", paths.dataDir)
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

// platformPaths returns the canonical directory layout for the current OS,
// respecting any user overrides via --data-dir.
func platformPaths() installPaths {
	var p installPaths
	switch runtime.GOOS {
	case "linux":
		p = installPaths{
			binDir:        "/usr/local/bin",
			configDir:     "/etc/edr",
			dataDir:       "/var/lib/edr",
			logDir:        "/var/log/edr",
			rulesDir:      "/etc/edr/rules",
			quarantineDir: "/var/lib/edr/quarantine",
		}
	case "darwin":
		p = installPaths{
			binDir:        "/usr/local/bin",
			configDir:     "/Library/Application Support/EDR/config",
			dataDir:       "/Library/Application Support/EDR",
			logDir:        "/Library/Logs/EDR",
			rulesDir:      "/Library/Application Support/EDR/rules",
			quarantineDir: "/Library/Application Support/EDR/quarantine",
		}
	case "windows":
		p = installPaths{
			binDir:        `C:\Program Files\EDR\bin`,
			configDir:     `C:\ProgramData\EDR\config`,
			dataDir:       `C:\ProgramData\EDR`,
			logDir:        `C:\ProgramData\EDR\logs`,
			rulesDir:      `C:\ProgramData\EDR\rules`,
			quarantineDir: `C:\ProgramData\EDR\quarantine`,
		}
	default:
		p = installPaths{
			binDir:    "/usr/local/bin",
			configDir: "/etc/edr",
			dataDir:   "/var/lib/edr",
			logDir:    "/var/log/edr",
			rulesDir:  "/etc/edr/rules",
		}
	}

	if flagDataDir != "" {
		p.dataDir = flagDataDir
		p.quarantineDir = filepath.Join(flagDataDir, "quarantine")
		p.rulesDir = filepath.Join(flagDataDir, "rules")
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
		out, err := exec.Command("net", "session").CombinedOutput()
		if err != nil {
			_ = out
			return fmt.Errorf("this operation requires administrator privileges; re-run in an elevated prompt")
		}
	}
	return nil
}

// generateConfig creates an initial agent.yaml with sane defaults and a
// freshly generated agent ID.
func generateConfig(dst string, paths installPaths) error {
	cfg := config.Defaults()

	cfg.Agent.ID = uuid.NewString()
	cfg.Agent.Name = hostname()
	cfg.Agent.Environment = "enterprise"
	cfg.Agent.DataDir = paths.dataDir
	cfg.Agent.TempDir = filepath.Join(paths.dataDir, "tmp")

	cfg.Logging.Level = "info"
	cfg.Logging.AlertFile = filepath.Join(paths.logDir, "alerts.jsonl")
	cfg.Logging.AuditFile = filepath.Join(paths.logDir, "audit.jsonl")

	cfg.Detection.Sigma.RulesDir = paths.rulesDir
	cfg.Detection.YARA.RulesDir = filepath.Join(paths.rulesDir, "yara")
	cfg.Detection.IOC.HashDBPath = filepath.Join(paths.dataDir, "ioc", "hashes.db")
	cfg.Detection.IOC.IPDBPath = filepath.Join(paths.dataDir, "ioc", "ips.db")
	cfg.Detection.IOC.DomainDBPath = filepath.Join(paths.dataDir, "ioc", "domains.db")

	cfg.Response.Quarantine.Dir = paths.quarantineDir
	cfg.Response.Forensics.OutputDir = filepath.Join(paths.dataDir, "forensics")

	cfg.ML.ModelsDir = filepath.Join(paths.dataDir, "models")

	cfg.LLM.RAG.VectorDBPath = filepath.Join(paths.dataDir, "vectordb")

	cfg.SelfProtect.Enabled = true
	cfg.SelfProtect.Watchdog = true
	cfg.SelfProtect.IntegrityCheck = true

	data, err := yaml.Marshal(cfg)
	if err != nil {
		return fmt.Errorf("marshaling config: %w", err)
	}
	return os.WriteFile(dst, data, 0640)
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

// stopService halts the currently running EDR agent service.
func stopService() error {
	switch runtime.GOOS {
	case "linux":
		return runCmd("systemctl", "stop", "edr-agent")
	case "darwin":
		return runCmd("launchctl", "unload", "/Library/LaunchDaemons/com.razatech.edr-agent.plist")
	case "windows":
		return runCmd("sc", "stop", "EDRAgent")
	default:
		return fmt.Errorf("unsupported platform: %s", runtime.GOOS)
	}
}

// removeService unregisters the platform service definition files.
func removeService(paths installPaths) error {
	switch runtime.GOOS {
	case "linux":
		_ = runCmd("systemctl", "disable", "edr-agent")
		return os.Remove("/etc/systemd/system/edr-agent.service")
	case "darwin":
		return os.Remove("/Library/LaunchDaemons/com.razatech.edr-agent.plist")
	case "windows":
		return runCmd("sc", "delete", "EDRAgent")
	default:
		return nil
	}
}

const systemdUnit = `[Unit]
Description=EDR Endpoint Detection and Response Agent
After=network-online.target
Wants=network-online.target
Documentation=https://github.com/razatechofficial/edr

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
ReadWritePaths={{.DataDir}} {{.LogDir}}
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
	}{
		AgentBin:   agentBin,
		ConfigPath: configPath,
		DataDir:    paths.dataDir,
		LogDir:     paths.logDir,
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
    <true/>
    <key>StandardOutPath</key>
    <string>/Library/Logs/EDR/agent.stdout.log</string>
    <key>StandardErrorPath</key>
    <string>/Library/Logs/EDR/agent.stderr.log</string>
    <key>HardResourceLimits</key>
    <dict>
        <key>NumberOfFiles</key>
        <integer>65536</integer>
    </dict>
</dict>
</plist>
`

// installLaunchDaemon writes a launchd plist and loads the daemon.
func installLaunchDaemon(agentBin, configPath string) error {
	tmpl, err := template.New("plist").Parse(launchdPlist)
	if err != nil {
		return fmt.Errorf("parsing plist template: %w", err)
	}

	plistPath := "/Library/LaunchDaemons/com.razatech.edr-agent.plist"
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

	if err := runCmd("launchctl", "load", plistPath); err != nil {
		return fmt.Errorf("launchctl load: %w", err)
	}
	fmt.Println("    daemon loaded")
	return nil
}

// installWindowsService registers the agent as a Windows Service using sc.exe.
func installWindowsService(agentBin, configPath string) error {
	binPath := fmt.Sprintf(`"%s" run --config "%s"`, agentBin, configPath)
	if err := runCmd("sc", "create", "EDRAgent",
		"binPath=", binPath,
		"start=", "auto",
		"DisplayName=", "EDR Agent",
	); err != nil {
		return fmt.Errorf("sc create: %w", err)
	}

	if err := runCmd("sc", "description", "EDRAgent",
		"Endpoint Detection and Response agent by RazaTech",
	); err != nil {
		fmt.Printf("    warning: setting description: %v\n", err)
	}

	if err := runCmd("sc", "failure", "EDRAgent",
		"reset=", "86400",
		"actions=", "restart/5000/restart/10000/restart/30000",
	); err != nil {
		fmt.Printf("    warning: setting recovery: %v\n", err)
	}

	if err := runCmd("sc", "start", "EDRAgent"); err != nil {
		return fmt.Errorf("sc start: %w", err)
	}
	fmt.Println("    Windows Service installed and started")
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

// findAgentBinary locates the agent binary in common build output paths
// relative to the installer working directory.
func findAgentBinary() (string, error) {
	suffix := fmt.Sprintf("-%s-%s", runtime.GOOS, runtime.GOARCH)
	if runtime.GOOS == "windows" {
		suffix += ".exe"
	}

	candidates := []string{
		filepath.Join("bin", "edr-agent"+suffix),
		filepath.Join(".", agentBinaryName()),
		agentBinaryName(),
	}

	for _, c := range candidates {
		if info, err := os.Stat(c); err == nil && !info.IsDir() {
			abs, _ := filepath.Abs(c)
			return abs, nil
		}
	}
	return "", fmt.Errorf("agent binary not found; tried: %s", strings.Join(candidates, ", "))
}

// findEdrctlBinary locates the edrctl binary in common build output paths.
func findEdrctlBinary() string {
	suffix := fmt.Sprintf("-%s-%s", runtime.GOOS, runtime.GOARCH)
	if runtime.GOOS == "windows" {
		suffix += ".exe"
	}

	candidates := []string{
		filepath.Join("bin", "edrctl"+suffix),
		filepath.Join(".", edrctlBinaryName()),
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
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}
