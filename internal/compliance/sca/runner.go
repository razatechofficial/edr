package sca

import (
	"context"
	"log/slog"
	"runtime"
	"sync"
	"time"
)

// ScanCompleteSummary aggregates one full SCA scan across all applicable policies.
type ScanCompleteSummary struct {
	Passed             int
	Failed             int
	Errors             int
	Skipped            int
	PoliciesTotal      int
	PoliciesApplicable int
	Duration           time.Duration
}

// FindingHandler receives each SCA check result.
type FindingHandler func(CheckResult)

// ScanCompleteHandler is invoked once after each full scan finishes.
type ScanCompleteHandler func(ScanCompleteSummary)

// Runner executes SCA policies on a schedule (scan_on_start + interval).
type Runner struct {
	rulesDir          string
	scanOnStart       bool
	interval          time.Duration
	maxConcurrent     int
	commandsEnabled   bool
	commandTimeout    time.Duration
	logger            *slog.Logger
	onFinding         FindingHandler
	onScanComplete    ScanCompleteHandler

	mu       sync.Mutex
	policies []Policy
}

// RunnerConfig configures the SCA runner.
type RunnerConfig struct {
	RulesDir          string
	ScanOnStart       bool
	Interval          time.Duration
	MaxConcurrent     int
	CommandsEnabled   bool
	CommandTimeout    time.Duration
	Logger            *slog.Logger
	OnFinding         FindingHandler
	OnScanComplete    ScanCompleteHandler
}

// NewRunner loads policies and returns a runner. Policies are loaded eagerly so
// misconfiguration fails at startup.
func NewRunner(cfg RunnerConfig) (*Runner, error) {
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.Interval <= 0 {
		cfg.Interval = 12 * time.Hour
	}
	if cfg.MaxConcurrent <= 0 {
		cfg.MaxConcurrent = 1
	}
	if cfg.CommandTimeout <= 0 {
		cfg.CommandTimeout = 30 * time.Second
	}
	policies, err := LoadPolicies(cfg.RulesDir)
	if err != nil {
		return nil, err
	}
	return &Runner{
		rulesDir:        cfg.RulesDir,
		scanOnStart:     cfg.ScanOnStart,
		interval:        cfg.Interval,
		maxConcurrent:   cfg.MaxConcurrent,
		commandsEnabled: cfg.CommandsEnabled,
		commandTimeout:  cfg.CommandTimeout,
		logger:          cfg.Logger,
		onFinding:       cfg.OnFinding,
		onScanComplete:  cfg.OnScanComplete,
		policies:        policies,
	}, nil
}

// Run blocks until ctx is cancelled. Executes an immediate scan when scan_on_start is set.
func (r *Runner) Run(ctx context.Context) error {
	r.logger.Info("sca runner started",
		"os", runtime.GOOS,
		"policies", len(r.policies),
		"scan_on_start", r.scanOnStart,
		"interval", r.interval,
	)
	if r.scanOnStart {
		r.scanAll(ctx)
	}
	ticker := time.NewTicker(r.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			r.scanAll(ctx)
		}
	}
}

func (r *Runner) scanAll(ctx context.Context) {
	start := time.Now()
	evalCfg := r.evalConfig()
	applicable := FilterApplicablePolicies(ctx, r.policies, evalCfg, r.logger)
	r.logger.Info("sca scan started",
		"policies_total", len(r.policies),
		"policies_applicable", len(applicable),
	)
	var totalPassed, totalFailed, totalErr, totalSkipped int
	for _, p := range applicable {
		select {
		case <-ctx.Done():
			return
		default:
		}
		summary := EvaluatePolicy(ctx, p, evalCfg)
		totalPassed += summary.Passed
		totalFailed += summary.Failed
		totalErr += summary.Errors
		totalSkipped += summary.Skipped
		for _, res := range summary.Results {
			if r.onFinding != nil {
				r.onFinding(res)
			}
		}
		r.logger.Info("sca policy complete",
			"policy_id", summary.PolicyID,
			"passed", summary.Passed,
			"failed", summary.Failed,
			"errors", summary.Errors,
			"skipped", summary.Skipped,
		)
	}
	r.logger.Info("sca scan complete",
		"duration", time.Since(start),
		"passed", totalPassed,
		"failed", totalFailed,
		"errors", totalErr,
		"skipped", totalSkipped,
	)
	if r.onScanComplete != nil {
		r.onScanComplete(ScanCompleteSummary{
			Passed:             totalPassed,
			Failed:             totalFailed,
			Errors:             totalErr,
			Skipped:            totalSkipped,
			PoliciesTotal:      len(r.policies),
			PoliciesApplicable: len(applicable),
			Duration:           time.Since(start),
		})
	}
}

func (r *Runner) evalConfig() EvalConfig {
	cfg := defaultEvalConfig()
	cfg.CommandsEnabled = r.commandsEnabled
	if r.commandTimeout > 0 {
		cfg.CommandTimeout = r.commandTimeout
	}
	return cfg
}

// PolicyCount returns the number of loaded policies.
func (r *Runner) PolicyCount() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.policies)
}
