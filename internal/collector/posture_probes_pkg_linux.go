//go:build linux

package collector

import (
	"context"
	"os/exec"
	"strings"
	"time"
)

// posturePkgIntegrityLinux runs a bounded package integrity probe (rpm -Va / debsums).
func posturePkgIntegrityLinux(ctx context.Context) map[string]any {
	ctx2, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()
	if _, err := exec.LookPath("rpm"); err == nil {
		out, err := exec.CommandContext(ctx2, "rpm", "-Va", "--nodigest", "--nosignature").Output()
		if err != nil {
			return map[string]any{"backend": "rpm", "status": "error", "detail": err.Error()}
		}
		lines := strings.Split(strings.TrimSpace(string(out)), "\n")
		n := 0
		for _, ln := range lines {
			if strings.TrimSpace(ln) != "" {
				n++
			}
		}
		return map[string]any{"backend": "rpm", "anomaly_lines": n, "capped": n >= 500}
	}
	if _, err := exec.LookPath("debsums"); err == nil {
		out, err := exec.CommandContext(ctx2, "debsums", "-s").Output()
		if err != nil {
			return map[string]any{"backend": "debsums", "status": "error", "detail": err.Error()}
		}
		lines := strings.Split(strings.TrimSpace(string(out)), "\n")
		n := 0
		for _, ln := range lines {
			if strings.Contains(strings.ToLower(ln), "failed") {
				n++
			}
		}
		return map[string]any{"backend": "debsums", "failed_lines": n}
	}
	return map[string]any{"status": "skipped", "reason": "no_rpm_or_debsums"}
}
