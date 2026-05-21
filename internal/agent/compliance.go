package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"github.com/google/uuid"

	"github.com/razatechofficial/edr/internal/collector"
	"github.com/razatechofficial/edr/internal/compliance/sca"
	"github.com/razatechofficial/edr/internal/schema"
	"github.com/razatechofficial/edr/pkg/ocsf"
)

func (a *Agent) initCompliance() error {
	if !a.cfg.Compliance.Enabled {
		return nil
	}
	rulesDir := a.cfg.Compliance.RulesDir
	if rulesDir == "" {
		rulesDir = "rules/compliance/sca"
	}
	if !filepath.IsAbs(rulesDir) {
		if wd, err := os.Getwd(); err == nil {
			rulesDir = filepath.Join(wd, rulesDir)
		}
	}
	interval := time.Duration(a.cfg.Compliance.IntervalHours) * time.Hour
	if interval <= 0 {
		interval = 12 * time.Hour
	}
	endpointID := a.cfg.Service.EndpointID
	if endpointID == "" {
		endpointID = a.cfg.Agent.ID
	}
	host, _ := os.Hostname()
	product := ocsf.DefaultProduct(a.cfg.Agent.Version)

	runner, err := sca.NewRunner(sca.RunnerConfig{
		RulesDir:        rulesDir,
		ScanOnStart:     a.cfg.Compliance.ScanOnStart,
		Interval:        interval,
		CommandsEnabled: a.cfg.Compliance.CommandsEnabled,
		CommandTimeout:  time.Duration(a.cfg.Compliance.CommandTimeoutSec) * time.Second,
		Logger:          a.logger,
		OnFinding: func(res sca.CheckResult) {
			a.emitComplianceFinding(res, endpointID, host, product)
		},
		OnScanComplete: func(summary sca.ScanCompleteSummary) {
			a.emitComplianceScanSummary(summary, endpointID, host, product)
		},
	})
	if err != nil {
		return err
	}
	a.scaRunner = runner
	a.logger.Info("compliance sca initialized",
		"rules_dir", rulesDir,
		"policies", runner.PolicyCount(),
		"scan_on_start", a.cfg.Compliance.ScanOnStart,
		"interval", interval,
		"os", runtime.GOOS,
	)
	return nil
}

func (a *Agent) emitComplianceFinding(res sca.CheckResult, endpointID, host string, product ocsf.Product) {
	if res.Result == "passed" && !a.cfg.Compliance.EmitPassedFindings {
		return
	}
	now := time.Now().UTC()
	env := ocsf.FromComplianceFinding(ocsf.ComplianceInput{
		EndpointID:  endpointID,
		Hostname:    host,
		OS:          runtime.GOOS,
		PolicyID:    res.PolicyID,
		PolicyName:  res.PolicyName,
		CheckID:     res.CheckID,
		Title:       res.Title,
		Description: res.Description,
		Remediation: res.Remediation,
		Result:      res.Result,
		Compliance:  res.Compliance,
		MITRE:       res.MITRE,
		Timestamp:   now,
	}, product)
	ocsfMap := map[string]any{}
	if b, err := json.Marshal(env); err == nil {
		_ = json.Unmarshal(b, &ocsfMap)
	}
	ev := &schema.ComplianceFindingEvent{
		BaseEvent: schema.BaseEvent{
			SchemaVersion: schema.SchemaVersionV1,
			EventType:     schema.EventCompliance,
			EndpointID:    endpointID,
			Timestamp:     now,
			Hostname:      host,
			OS:            runtime.GOOS,
			OCSF:          ocsfMap,
		},
		PolicyID:    res.PolicyID,
		PolicyName:  res.PolicyName,
		CheckID:     res.CheckID,
		Title:       res.Title,
		Description: res.Description,
		Remediation: res.Remediation,
		Result:      res.Result,
		Error:       res.Error,
		Compliance:  res.Compliance,
		MITRE:       res.MITRE,
	}
	a.maybeForwardTelemetry(context.Background(), &collector.Telemetry{Compliance: ev})
	if res.Result == "failed" {
		if err := a.handleAlerts([]schema.Alert{complianceFindingToAlert(ev)}); err != nil {
			a.logger.Warn("sca alert emit failed", "error", err)
		}
		a.logger.Warn("sca check failed",
			"policy_id", res.PolicyID,
			"check_id", res.CheckID,
			"title", res.Title,
		)
	}
}

func (a *Agent) emitComplianceScanSummary(summary sca.ScanCompleteSummary, endpointID, host string, product ocsf.Product) {
	now := time.Now().UTC()
	env := ocsf.FromComplianceScan(ocsf.ComplianceScanInput{
		EndpointID:         endpointID,
		Hostname:           host,
		OS:                 runtime.GOOS,
		Timestamp:          now,
		Passed:             summary.Passed,
		Failed:             summary.Failed,
		Errors:             summary.Errors,
		Skipped:            summary.Skipped,
		PoliciesTotal:      summary.PoliciesTotal,
		PoliciesApplicable: summary.PoliciesApplicable,
		DurationMs:         summary.Duration.Milliseconds(),
	}, product)
	ocsfMap := map[string]any{}
	if b, err := json.Marshal(env); err == nil {
		_ = json.Unmarshal(b, &ocsfMap)
	}
	ev := &schema.ComplianceScanSummaryEvent{
		BaseEvent: schema.BaseEvent{
			SchemaVersion: schema.SchemaVersionV1,
			EventType:     schema.EventComplianceScan,
			EndpointID:    endpointID,
			Timestamp:     now,
			Hostname:      host,
			OS:            runtime.GOOS,
			OCSF:          ocsfMap,
		},
		Passed:             summary.Passed,
		Failed:             summary.Failed,
		Errors:             summary.Errors,
		Skipped:            summary.Skipped,
		PoliciesTotal:      summary.PoliciesTotal,
		PoliciesApplicable: summary.PoliciesApplicable,
		DurationMs:         summary.Duration.Milliseconds(),
	}
	a.maybeForwardTelemetry(context.Background(), &collector.Telemetry{ComplianceScan: ev})
	if summary.Failed > 0 || summary.Errors > 0 {
		if err := a.handleAlerts([]schema.Alert{complianceScanSummaryToAlert(ev)}); err != nil {
			a.logger.Warn("sca scan summary alert emit failed", "error", err)
		}
	}
	a.logger.Info("sca scan summary",
		"passed", summary.Passed,
		"failed", summary.Failed,
		"errors", summary.Errors,
		"policies_applicable", summary.PoliciesApplicable,
		"duration", summary.Duration,
	)
}

func complianceScanSummaryToAlert(ev *schema.ComplianceScanSummaryEvent) schema.Alert {
	if ev == nil {
		return schema.Alert{}
	}
	return schema.Alert{
		SchemaVersion: schema.SchemaVersionV1,
		AlertID:       uuid.NewString(),
		RuleID:        "compliance/sca_scan",
		EndpointID:    ev.EndpointID,
		Severity:      schema.SeverityMedium,
		Score:         55,
		Title:         "SCA scan completed with failures",
		Description:   fmt.Sprintf("passed=%d failed=%d errors=%d skipped=%d policies=%d", ev.Passed, ev.Failed, ev.Errors, ev.Skipped, ev.PoliciesApplicable),
		Timestamp:     ev.Timestamp,
	}
}

func complianceFindingToAlert(ev *schema.ComplianceFindingEvent) schema.Alert {
	if ev == nil {
		return schema.Alert{}
	}
	ruleID := fmt.Sprintf("compliance/%s", ev.PolicyID)
	if ev.CheckID != 0 {
		ruleID = fmt.Sprintf("compliance/%s/%d", ev.PolicyID, ev.CheckID)
	}
	sev := schema.SeverityMedium
	score := 60
	if ev.PolicyID == "posture" {
		sev = schema.SeverityHigh
		score = 75
	}
	desc := ev.Description
	if desc == "" {
		desc = ev.Remediation
	}
	return schema.Alert{
		SchemaVersion: schema.SchemaVersionV1,
		AlertID:       uuid.NewString(),
		RuleID:        ruleID,
		EndpointID:    ev.EndpointID,
		Severity:      sev,
		Score:         score,
		Title:         ev.Title,
		Description:   desc,
		Timestamp:     ev.Timestamp,
	}
}

func (a *Agent) handleComplianceTelemetry(ctx context.Context, ev *schema.ComplianceFindingEvent) error {
	if ev == nil {
		return nil
	}
	if ev.Result != "failed" {
		return nil
	}
	return a.handleAlerts([]schema.Alert{complianceFindingToAlert(ev)})
}
