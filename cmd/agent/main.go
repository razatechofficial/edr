package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"

	"github.com/spf13/cobra"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"

	"github.com/razatechofficial/edr/internal/agent"
	"github.com/razatechofficial/edr/internal/config"
)

var (
	Version   = "dev"
	BuildTime = "unknown"
	Commit    = "none"
)

var (
	configPath string
	dataDir    string
	logLevel   string
	debug      bool
	testMode   bool
	installSvc bool
	removeSvc  bool
	showVer    bool
)

func main() {
	root := &cobra.Command{
		Use:   "edr-agent",
		Short: "EDR endpoint detection and response agent",
		Long:  "Production EDR agent that collects telemetry, evaluates detection rules, and executes automated response actions.",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runAgent()
		},
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	root.PersistentFlags().StringVar(&configPath, "config", "configs/agent.example.yaml", "path to agent configuration file")
	root.PersistentFlags().StringVar(&dataDir, "data-dir", "", "override data directory")
	root.PersistentFlags().StringVar(&logLevel, "log-level", "", "override log level")
	root.PersistentFlags().BoolVar(&debug, "debug", false, "enable debug logging with console output")
	root.PersistentFlags().BoolVar(&testMode, "test-mode", false, "run built-in validation suite and exit")
	root.PersistentFlags().BoolVar(&installSvc, "install", false, "install as system service")
	root.PersistentFlags().BoolVar(&removeSvc, "uninstall", false, "uninstall system service")
	root.PersistentFlags().BoolVar(&showVer, "version", false, "print version and exit")

	runCmd := &cobra.Command{
		Use:   "run",
		Short: "Start the EDR agent",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runAgent()
		},
	}

	versionCmd := &cobra.Command{
		Use:   "version",
		Short: "Print version information",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Printf("edr-agent %s (built %s)\n  commit:  %s\n  go:      %s\n  os/arch: %s/%s\n",
				Version, BuildTime, Commit, runtime.Version(), runtime.GOOS, runtime.GOARCH)
		},
	}

	root.AddCommand(runCmd, versionCmd)

	if err := root.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func newLogger(logMode string, cfg config.Config) (*zap.Logger, error) {
	mode := strings.ToLower(strings.TrimSpace(logMode))
	if mode == "" {
		mode = "structured"
	}
	encoderCfg := zap.NewProductionEncoderConfig()
	encoderCfg.TimeKey = "ts"
	encoderCfg.EncodeTime = zapcore.ISO8601TimeEncoder
	encoderCfg.EncodeDuration = zapcore.StringDurationEncoder
	prettyCfg := zap.NewDevelopmentEncoderConfig()
	prettyCfg.EncodeLevel = zapcore.CapitalColorLevelEncoder
	prettyCfg.EncodeTime = zapcore.TimeEncoderOfLayout("15:04:05")

	level := zap.NewAtomicLevelAt(zap.InfoLevel)
	if debug || strings.EqualFold(cfg.Agent.LogLevel, "debug") {
		level.SetLevel(zap.DebugLevel)
	}

	cores := make([]zapcore.Core, 0, 3)
	if mode == "structured" || mode == "dual" {
		cores = append(cores, zapcore.NewCore(zapcore.NewJSONEncoder(encoderCfg), zapcore.AddSync(os.Stdout), level))
	}
	if mode == "pretty" || mode == "dual" || debug {
		cores = append(cores, zapcore.NewCore(zapcore.NewConsoleEncoder(prettyCfg), zapcore.AddSync(os.Stdout), level))
	}
	if len(cores) == 0 {
		cores = append(cores, zapcore.NewCore(zapcore.NewJSONEncoder(encoderCfg), zapcore.AddSync(os.Stdout), level))
	}

	// Persist agent runtime logs for production troubleshooting.
	logPath := filepath.Join(cfg.Agent.DataDir, "logs", "agent.log")
	if err := os.MkdirAll(filepath.Dir(logPath), 0o755); err == nil {
		if f, err := os.OpenFile(logPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644); err == nil {
			cores = append(cores, zapcore.NewCore(zapcore.NewJSONEncoder(encoderCfg), zapcore.AddSync(f), level))
		}
	}

	// Keep operator logs clean; avoid file:line noise in production output.
	return zap.New(zapcore.NewTee(cores...)), nil
}

func installSlog(logger *zap.Logger) {
	if logger == nil {
		return
	}
	slog.SetDefault(slog.New(&zapSlogHandler{logger: logger}))
}

func runAgent() error {
	if installSvc && removeSvc {
		return errors.New("--install and --uninstall are mutually exclusive")
	}
	if showVer {
		fmt.Printf("edr-agent %s (built %s)\n", Version, BuildTime)
		return nil
	}
	if installSvc {
		return installService()
	}
	if removeSvc {
		return uninstallService()
	}
	if dataDir != "" {
		_ = os.Setenv("DATA_DIR", dataDir)
	}
	if logLevel != "" {
		_ = os.Setenv("LOG_LEVEL", logLevel)
	}

	cfg, err := config.Load(configPath)
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}
	logger, err := newLogger(cfg.Logging.Mode, cfg)
	if err != nil {
		return fmt.Errorf("initializing logger: %w", err)
	}
	defer func() { _ = logger.Sync() }()
	installSlog(logger)

	logger.Info("starting edr-agent",
		zap.String("version", Version),
		zap.String("commit", Commit),
		zap.String("built", BuildTime),
		zap.String("os", runtime.GOOS),
		zap.String("arch", runtime.GOARCH),
		zap.String("config", configPath),
	)

	// P2-17: lock down the agent process before loading any third-
	// party module. On Windows this enables PROCESS_MITIGATION_*
	// policies (no dynamic code, no remote-image loads, no extension
	// points). On other OSes this is a no-op stub. The boot posture
	// surfaces success/failure per policy so an operator can verify.
	_ = applyProcessMitigations(logger)

	if err := validateWindowsPPLBoot(cfg, logger); err != nil {
		return err
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Buffer so a second interrupt is not lost while graceful shutdown runs.
	sigCh := make(chan os.Signal, 8)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	defer signal.Stop(sigCh)

	go func() {
		sig := <-sigCh
		logger.Info("received signal, shutting down", zap.String("signal", sig.String()))
		cancel()
		// If something blocks during shutdown (alert I/O, detection engine Stop, etc.),
		// a second SIGINT/SIGTERM exits the process immediately.
		sig2 := <-sigCh
		logger.Warn("received second signal, exiting now", zap.String("signal", sig2.String()))
		os.Exit(0)
	}()

	a, err := agent.NewWithFiles(configPath)
	if err != nil {
		logger.Error("agent initialization failed", zap.Error(err))
		return fmt.Errorf("agent init: %w", err)
	}
	if testMode {
		exitCode := runValidationSuite(ctx, a, &cfg)
		if exitCode != 0 {
			return fmt.Errorf("validation suite failed with exit code %d", exitCode)
		}
		logger.Info("validation suite passed")
		return nil
	}

	logger.Info("agent initialized, entering main loop")

	if err := a.Run(ctx); err != nil {
		logger.Error("agent exited with error", zap.Error(err))
		return fmt.Errorf("agent run: %w", err)
	}

	logger.Info("agent stopped gracefully")
	return nil
}
