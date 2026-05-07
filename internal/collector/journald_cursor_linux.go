//go:build linux

package collector

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func (l *LogTargetsCollector) journaldCursorPath(idx int) string {
	dd := strings.TrimSpace(l.cfg.Agent.DataDir)
	if dd == "" {
		return ""
	}
	return filepath.Join(dd, fmt.Sprintf("journald_cursor_%d", idx))
}

func readJournaldCursor(path string) string {
	if path == "" {
		return ""
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

func writeJournaldCursor(path, cursor string) {
	if path == "" || cursor == "" {
		return
	}
	_ = os.WriteFile(path, []byte(cursor), 0o600)
}

// journaldMessageFromJSONLine extracts a display string and __CURSOR from one journalctl -o json line.
func journaldMessageFromJSONLine(line string) (msg, cursor string) {
	line = strings.TrimSpace(line)
	if line == "" {
		return "", ""
	}
	var obj map[string]any
	if err := json.Unmarshal([]byte(line), &obj); err != nil {
		return line, ""
	}
	if c, ok := obj["__CURSOR"].(string); ok {
		cursor = c
	}
	if m, ok := obj["MESSAGE"].(string); ok && m != "" {
		return m, cursor
	}
	return line, cursor
}
