package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"runtime"
	"syscall"

	"github.com/spf13/cobra"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"

	"github.com/razatechofficial/edr/internal/agent"
)

var (
	version   = "dev"
	commit    = "none"
	buildDate = "unknown"
)

var (
	configPath string
	debug      bool
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
	root.PersistentFlags().BoolVar(&debug, "debug", false, "enable debug logging with console output")

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
			fmt.Printf("edr-agent %s\n  commit:  %s\n  built:   %s\n  go:      %s\n  os/arch: %s/%s\n",
				version, commit, buildDate, runtime.Version(), runtime.GOOS, runtime.GOARCH)
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
	logger, err := newLogger()
	if err != nil {
		return fmt.Errorf("initializing logger: %w", err)
	}
	defer func() { _ = logger.Sync() }()

	logger.Info("starting edr-agent",
		zap.String("version", version),
		zap.String("commit", commit),
		zap.String("built", buildDate),
		zap.String("os", runtime.GOOS),
		zap.String("arch", runtime.GOARCH),
		zap.String("config", configPath),
	)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		sig := <-sigCh
		logger.Info("received signal, shutting down", zap.String("signal", sig.String()))
		cancel()
	}()

	a, err := agent.NewWithFiles(configPath)
	if err != nil {
		logger.Error("agent initialization failed", zap.Error(err))
		return fmt.Errorf("agent init: %w", err)
	}

	logger.Info("agent initialized, entering main loop")

	if err := a.Run(ctx); err != nil {
		logger.Error("agent exited with error", zap.Error(err))
		return fmt.Errorf("agent run: %w", err)
	}

	logger.Info("agent stopped gracefully")
	return nil
}
