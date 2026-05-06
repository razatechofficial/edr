//go:build linux

package collector

import (
	"bufio"
	"context"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"github.com/razatechofficial/edr/internal/schema"
)

func (l *LogTargetsCollector) collectJournaldSnapshot(ctx context.Context, st *logTargetRuntime) ([]Telemetry, uint64, error) {
	args := []string{"-n", "120", "--no-pager", "--output=json"}
	if u := strings.TrimSpace(st.target.Path); u != "" {
		args = append(args, "-u", u)
	}
	if q := strings.Fields(strings.TrimSpace(st.target.Query)); len(q) > 0 {
		args = append(args, q...)
	}
	c := exec.CommandContext(ctx, "journalctl", args...)
	b, err := c.CombinedOutput()
	if err != nil {
		return nil, uint64(len(b)), err
	}
	now := time.Now().UTC()
	var out []Telemetry
	sc := bufio.NewScanner(strings.NewReader(string(b)))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		if len(line) > logTailMaxLineBytes {
			line = line[:logTailMaxLineBytes]
		}
		out = append(out, Telemetry{File: &schema.FileEvent{
			BaseEvent: schema.BaseEvent{
				SchemaVersion: schema.SchemaVersionV1,
				EventType:     schema.EventFile,
				EndpointID:    l.endpointID,
				Timestamp:     now,
				Hostname:      l.hostname,
				OS:            runtime.GOOS,
			},
			Path:         firstNonEmpty(strings.TrimSpace(st.target.Path), "journald"),
			Operation:    "log_target_journald_line",
			ActorPID:     0,
			BytesWritten: uint64(len(line)),
		}})
	}
	return out, uint64(len(b)), nil
}
