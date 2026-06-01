package comms

import (
	"bufio"
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"sync"

	"github.com/razatechofficial/edr/internal/schema"
)

// AlertQueue stores alerts that failed to reach the control plane.
type AlertQueue struct {
	path string
	mu   sync.Mutex
}

// NewAlertQueue creates a JSONL queue at dataDir/controlplane-pending-alerts.jsonl.
func NewAlertQueue(dataDir string) *AlertQueue {
	if dataDir == "" {
		dataDir = "."
	}
	return &AlertQueue{path: filepath.Join(dataDir, "controlplane-pending-alerts.jsonl")}
}

// Enqueue appends an alert for later delivery.
func (q *AlertQueue) Enqueue(al schema.Alert) error {
	if q == nil {
		return nil
	}
	line, err := json.Marshal(al)
	if err != nil {
		return err
	}
	q.mu.Lock()
	defer q.mu.Unlock()
	f, err := os.OpenFile(q.path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = f.Write(append(line, '\n'))
	return err
}

// Drain reads up to limit queued alerts and removes them from the queue.
func (q *AlertQueue) Drain(limit int) ([]schema.Alert, error) {
	if q == nil {
		return nil, nil
	}
	if limit <= 0 {
		limit = 100
	}
	q.mu.Lock()
	defer q.mu.Unlock()

	f, err := os.Open(q.path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	defer f.Close()

	var alerts []schema.Alert
	var pending []schema.Alert
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}
		var al schema.Alert
		if err := json.Unmarshal(line, &al); err != nil {
			continue
		}
		if len(alerts) < limit {
			alerts = append(alerts, al)
		} else {
			pending = append(pending, al)
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	if len(alerts) == 0 {
		return nil, nil
	}
	if len(pending) == 0 {
		return alerts, os.Remove(q.path)
	}
	return alerts, rewriteQueue(q.path, pending)
}

// PendingCount returns the number of queued alerts waiting for delivery.
func (q *AlertQueue) PendingCount() (int, error) {
	if q == nil {
		return 0, nil
	}
	q.mu.Lock()
	defer q.mu.Unlock()

	f, err := os.Open(q.path)
	if err != nil {
		if os.IsNotExist(err) {
			return 0, nil
		}
		return 0, err
	}
	defer f.Close()

	count := 0
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		if len(bytes.TrimSpace(scanner.Bytes())) > 0 {
			count++
		}
	}
	return count, scanner.Err()
}

func rewriteQueue(path string, alerts []schema.Alert) error {
	tmp := path + ".tmp"
	out, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	for _, al := range alerts {
		line, err := json.Marshal(al)
		if err != nil {
			_ = out.Close()
			return err
		}
		if _, err := out.Write(append(line, '\n')); err != nil {
			_ = out.Close()
			return err
		}
	}
	if err := out.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
