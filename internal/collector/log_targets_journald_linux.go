//go:build linux

package collector

import (
	"bufio"
	"context"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"github.com/razatechofficial/edr/internal/schema"
)

func (l *LogTargetsCollector) collectJournaldSnapshot(ctx context.Context, st *logTargetRuntime) ([]Telemetry, uint64, error) {
	curPath := l.journaldCursorPath(st.idx)
	cursor := readJournaldCursor(curPath)

	baseArgs := []string{"--no-pager", "-o", "json", "-n", "200"}
	if u := strings.TrimSpace(st.target.Path); u != "" {
		baseArgs = append(baseArgs, "-u", u)
	}
	if q := strings.Fields(strings.TrimSpace(st.target.Query)); len(q) > 0 {
		baseArgs = append(baseArgs, q...)
	}

	run := func(afterCursor string) ([]byte, error) {
		args := append([]string{}, baseArgs...)
		if afterCursor != "" {
			args = append([]string{"--after-cursor=" + afterCursor}, args...)
		}
		c := exec.CommandContext(ctx, "journalctl", args...)
		return c.CombinedOutput()
	}

	b, err := run(cursor)
	if err != nil && cursor != "" && curPath != "" {
		_ = os.Remove(curPath)
		b, err = run("")
	}
	if err != nil {
		return nil, uint64(len(b)), err
	}

	now := time.Now().UTC()
	var out []Telemetry
	var lastCursor string
	sc := bufio.NewScanner(strings.NewReader(string(b)))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		msg, cur := journaldMessageFromJSONLine(line)
		if cur != "" {
			lastCursor = cur
		}
		if len(msg) > logTailMaxLineBytes {
			msg = msg[:logTailMaxLineBytes]
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
			BytesWritten: uint64(len(msg)),
		}})
	}
	if lastCursor != "" {
		writeJournaldCursor(curPath, lastCursor)
	}
	return out, uint64(len(b)), nil
}
