package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"runtime"
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

func newLogger() (*zap.Logger, error) {
	if debug {
		cfg := zap.NewDevelopmentConfig()
		cfg.EncoderConfig.EncodeLevel = zapcore.CapitalColorLevelEncoder
		return cfg.Build()
	}
	cfg := zap.NewProductionConfig()
	cfg.EncoderConfig.TimeKey = "ts"
	cfg.EncoderConfig.EncodeTime = zapcore.ISO8601TimeEncoder
	return cfg.Build()
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

	logger, err := newLogger()
	if err != nil {
		return fmt.Errorf("initializing logger: %w", err)
	}
	defer func() { _ = logger.Sync() }()

	logger.Info("starting edr-agent",
		zap.String("version", Version),
		zap.String("commit", Commit),
		zap.String("built", BuildTime),
		zap.String("os", runtime.GOOS),
		zap.String("arch", runtime.GOARCH),
		zap.String("config", configPath),
	)

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
		cfg, cfgErr := config.Load(configPath)
		if cfgErr != nil {
			return fmt.Errorf("config load for test mode: %w", cfgErr)
		}
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
