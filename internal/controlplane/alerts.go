package controlplane

import (
	"bufio"
	"bytes"
	"encoding/json"
	"os"
)

// ListRecentAlerts returns the newest alert entries from the on-disk JSONL log.
func (r *Registry) ListRecentAlerts(limit int) ([]map[string]any, error) {
	if limit <= 0 {
		limit = 50
	}
	f, err := os.Open(r.alertsPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	defer f.Close()

	var lines []string
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		line := bytes.TrimSpace(scanner.Bytes())
		if len(line) == 0 {
			continue
		}
		lines = append(lines, string(line))
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	if len(lines) == 0 {
		return nil, nil
	}
	if len(lines) > limit {
		lines = lines[len(lines)-limit:]
	}
	out := make([]map[string]any, 0, len(lines))
	for _, line := range lines {
		var entry map[string]any
		if err := json.Unmarshal([]byte(line), &entry); err != nil {
			continue
		}
		out = append(out, entry)
	}
	return out, nil
}
