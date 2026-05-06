//go:build linux

package collector

import (
	"context"
	"os/exec"
	"strings"
)

func (l *LogTargetsCollector) collectJournaldSnapshot(ctx context.Context, st *logTargetRuntime) (uint64, error) {
	args := []string{"-n", "120", "--no-pager", "--output=json"}
	if u := strings.TrimSpace(st.target.Path); u != "" {
		args = append(args, "-u", u)
	}
	if q := strings.Fields(strings.TrimSpace(st.target.Query)); len(q) > 0 {
		args = append(args, q...)
	}
	c := exec.CommandContext(ctx, "journalctl", args...)
	b, err := c.CombinedOutput()
	return uint64(len(b)), err
}
