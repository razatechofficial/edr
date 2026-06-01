package agent

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/razatechofficial/edr/internal/comms"
	"github.com/razatechofficial/edr/pkg/protocol"
)

func (a *Agent) controlPlanePolicyHashPath() string {
	dataDir := a.cfg.Agent.DataDir
	if dataDir == "" {
		dataDir = "/var/lib/edr"
	}
	return filepath.Join(dataDir, "controlplane-policy.hash")
}

func (a *Agent) readControlPlanePolicyHash() string {
	data, err := os.ReadFile(a.controlPlanePolicyHashPath())
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}

func (a *Agent) saveControlPlanePolicyHash(hash string) error {
	if strings.TrimSpace(hash) == "" {
		return nil
	}
	path := a.controlPlanePolicyHashPath()
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return err
	}
	return os.WriteFile(path, []byte(hash+"\n"), 0o600)
}

func (a *Agent) controlPlaneRulesRoot() (string, error) {
	yaraDir := strings.TrimSpace(a.cfg.Detection.YARA.RulesDir)
	if yaraDir != "" {
		return filepath.Dir(yaraDir), nil
	}
	sigmaDir := strings.TrimSpace(a.cfg.Detection.Sigma.RulesDir)
	if sigmaDir != "" {
		return filepath.Dir(sigmaDir), nil
	}
	dataDir := a.cfg.Agent.DataDir
	if dataDir == "" {
		dataDir = "/var/lib/edr"
	}
	return filepath.Join(dataDir, "rules"), nil
}

func (a *Agent) applyControlPlanePolicy(ctx context.Context, resp *protocol.PolicyResponse) error {
	if resp == nil || !resp.GetChanged() {
		return nil
	}
	if len(resp.GetRuleBundles()) == 0 {
		return a.saveControlPlanePolicyHash(resp.GetPolicyHash())
	}
	if !a.cfg.Detection.YARA.Enabled && !a.cfg.Detection.Sigma.Enabled && !a.cfg.Detection.IOC.Enabled {
		return fmt.Errorf("control plane policy requires at least one detection engine enabled")
	}

	rulesRoot, err := a.controlPlaneRulesRoot()
	if err != nil {
		return err
	}
	for _, bundle := range resp.GetRuleBundles() {
		if bundle == nil {
			continue
		}
		format := strings.ToLower(strings.TrimSpace(bundle.GetFormat()))
		if format != "" && format != "tar.gz" && format != "tgz" {
			a.logger.Warn("skipping unsupported rule bundle format",
				"bundle", bundle.GetName(),
				"format", bundle.GetFormat(),
			)
			continue
		}
		if err := comms.VerifyRuleBundle(
			bundle.GetName(),
			bundle.GetData(),
			bundle.GetHash(),
			bundle.GetSignature(),
			a.cfg.PolicyVerifyPubKeyPath,
		); err != nil {
			return err
		}
		if err := comms.ApplyRuleBundleTarGz(bundle.GetName(), bundle.GetData(), rulesRoot); err != nil {
			return err
		}
		a.logger.Info("control plane rule bundle extracted",
			"bundle", bundle.GetName(),
			"version", bundle.GetVersion(),
			"rules_root", rulesRoot,
		)
	}

	if a.advEngine != nil {
		if err := a.advEngine.Reload(); err != nil {
			return fmt.Errorf("reload detection engine: %w", err)
		}
		stats := a.advEngine.Stats()
		a.logger.Info("detection rules reloaded after policy sync",
			"yara_rules", stats.RulesLoaded.YARA,
			"sigma_rules", stats.RulesLoaded.Sigma,
			"ioc_enabled", a.cfg.Detection.IOC.Enabled,
		)
	}

	return a.saveControlPlanePolicyHash(resp.GetPolicyHash())
}

func (a *Agent) controlPlaneRulesLoaded() int {
	if a.advEngine != nil {
		stats := a.advEngine.Stats()
		return stats.RulesLoaded.YARA + stats.RulesLoaded.Sigma + stats.RulesLoaded.Behavioral
	}
	return len(a.ruleSet.Rules)
}
