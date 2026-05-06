package collector

import (
	"strings"

	"github.com/razatechofficial/edr/internal/config"
)

// EffectiveLogTargets merges monitoring.log_targets with legacy additional_log_tail_paths
// (each path becomes type=file). Duplicates by type+path+query are dropped.
func EffectiveLogTargets(cfg config.Config) []config.LogTarget {
	seen := map[string]struct{}{}
	key := func(t config.LogTarget) string {
		return strings.ToLower(strings.TrimSpace(t.Type)) + "\x00" + strings.TrimSpace(t.Path) + "\x00" + strings.TrimSpace(t.Query)
	}
	var out []config.LogTarget
	for _, lt := range cfg.Monitoring.LogTargets {
		ty := strings.ToLower(strings.TrimSpace(lt.Type))
		if ty == "" {
			continue
		}
		cp := lt
		cp.Type = ty
		k := key(cp)
		if _, ok := seen[k]; ok {
			continue
		}
		seen[k] = struct{}{}
		out = append(out, cp)
	}
	for _, p := range NormalizeAdditionalLogTailPaths(cfg.Monitoring.AdditionalLogTailPaths) {
		lt := config.LogTarget{Type: "file", Path: p}
		k := key(lt)
		if _, ok := seen[k]; ok {
			continue
		}
		seen[k] = struct{}{}
		out = append(out, lt)
	}
	return out
}

// LogTargetsBreadthConfigured reports whether any log target (including migrated file tails) is configured.
func LogTargetsBreadthConfigured(cfg config.Config) bool {
	return len(EffectiveLogTargets(cfg)) > 0
}
