package ml

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"go.uber.org/zap"
)

// FeedbackEntry represents a single analyst verdict on an alert.
type FeedbackEntry struct {
	AlertID   string    `json:"alert_id"`
	ModelName string    `json:"model_name"`
	Verdict   string    `json:"verdict"` // "tp" (true positive), "fp" (false positive), "benign", "malicious"
	Score     float64   `json:"score,omitempty"`
	Comment   string    `json:"comment,omitempty"`
	Analyst   string    `json:"analyst,omitempty"`
	Timestamp time.Time `json:"timestamp"`
}

// FeedbackIngester watches a directory for analyst feedback files (JSON or CSV)
// and enriches the TelemetryExporter's training data with verdicts.
type FeedbackIngester struct {
	mu          sync.Mutex
	watchDir    string
	exporter    *TelemetryExporter
	logger      *zap.Logger
	processed   map[string]struct{}
	entries     []FeedbackEntry
}

// NewFeedbackIngester creates an ingester that polls watchDir for feedback files.
func NewFeedbackIngester(watchDir string, exporter *TelemetryExporter, logger *zap.Logger) *FeedbackIngester {
	return &FeedbackIngester{
		watchDir:  watchDir,
		exporter:  exporter,
		logger:    logger,
		processed: make(map[string]struct{}),
	}
}

// Run polls for new feedback files until the context is done.
func (fi *FeedbackIngester) Run(done <-chan struct{}, interval time.Duration) {
	if interval <= 0 {
		interval = 30 * time.Second
	}
	fi.logger.Info("feedback ingester started", zap.String("dir", fi.watchDir))

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-done:
			fi.logger.Info("feedback ingester stopped")
			return
		case <-ticker.C:
			if err := fi.scan(); err != nil {
				fi.logger.Warn("feedback scan failed", zap.Error(err))
			}
		}
	}
}

// Entries returns all ingested feedback entries.
func (fi *FeedbackIngester) Entries() []FeedbackEntry {
	fi.mu.Lock()
	defer fi.mu.Unlock()
	out := make([]FeedbackEntry, len(fi.entries))
	copy(out, fi.entries)
	return out
}

func (fi *FeedbackIngester) scan() error {
	if err := os.MkdirAll(fi.watchDir, 0o750); err != nil {
		return err
	}

	dirEntries, err := os.ReadDir(fi.watchDir)
	if err != nil {
		return fmt.Errorf("read feedback dir: %w", err)
	}

	for _, de := range dirEntries {
		if de.IsDir() {
			continue
		}
		name := de.Name()

		fi.mu.Lock()
		_, done := fi.processed[name]
		fi.mu.Unlock()
		if done {
			continue
		}

		path := filepath.Join(fi.watchDir, name)
		var entries []FeedbackEntry

		switch {
		case strings.HasSuffix(name, ".json") || strings.HasSuffix(name, ".jsonl"):
			entries, err = fi.parseJSON(path)
		case strings.HasSuffix(name, ".csv"):
			entries, err = fi.parseCSV(path)
		default:
			continue
		}

		if err != nil {
			fi.logger.Warn("parse feedback file failed",
				zap.String("file", name), zap.Error(err))
			continue
		}

		fi.mu.Lock()
		fi.processed[name] = struct{}{}
		fi.entries = append(fi.entries, entries...)
		fi.mu.Unlock()

		for _, e := range entries {
			if fi.exporter != nil {
				fi.exporter.Record(ScoredEvent{
					Timestamp: e.Timestamp,
					ModelName: e.ModelName,
					Score:     e.Score,
					Category:  "feedback",
					Verdict:   e.Verdict,
					EventMeta: map[string]string{
						"alert_id": e.AlertID,
						"analyst":  e.Analyst,
						"comment":  e.Comment,
					},
				})
			}
		}

		fi.logger.Info("ingested feedback file",
			zap.String("file", name), zap.Int("entries", len(entries)))
	}
	return nil
}

func (fi *FeedbackIngester) parseJSON(path string) ([]FeedbackEntry, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	data = []byte(strings.TrimSpace(string(data)))
	if len(data) == 0 {
		return nil, nil
	}

	if data[0] == '[' {
		var entries []FeedbackEntry
		if err := json.Unmarshal(data, &entries); err != nil {
			return nil, fmt.Errorf("parse JSON array: %w", err)
		}
		return entries, nil
	}

	var entries []FeedbackEntry
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var entry FeedbackEntry
		if err := json.Unmarshal([]byte(line), &entry); err != nil {
			continue
		}
		if entry.Timestamp.IsZero() {
			entry.Timestamp = time.Now().UTC()
		}
		entries = append(entries, entry)
	}
	return entries, nil
}

func (fi *FeedbackIngester) parseCSV(path string) ([]FeedbackEntry, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	r := csv.NewReader(f)
	r.FieldsPerRecord = -1
	records, err := r.ReadAll()
	if err != nil {
		return nil, fmt.Errorf("read csv: %w", err)
	}

	if len(records) < 2 {
		return nil, nil
	}

	header := records[0]
	colIdx := make(map[string]int)
	for i, h := range header {
		colIdx[strings.ToLower(strings.TrimSpace(h))] = i
	}

	var entries []FeedbackEntry
	for _, row := range records[1:] {
		entry := FeedbackEntry{Timestamp: time.Now().UTC()}
		if idx, ok := colIdx["alert_id"]; ok && idx < len(row) {
			entry.AlertID = row[idx]
		}
		if idx, ok := colIdx["model_name"]; ok && idx < len(row) {
			entry.ModelName = row[idx]
		}
		if idx, ok := colIdx["verdict"]; ok && idx < len(row) {
			entry.Verdict = row[idx]
		}
		if idx, ok := colIdx["score"]; ok && idx < len(row) {
			entry.Score, _ = strconv.ParseFloat(row[idx], 64)
		}
		if idx, ok := colIdx["comment"]; ok && idx < len(row) {
			entry.Comment = row[idx]
		}
		if idx, ok := colIdx["analyst"]; ok && idx < len(row) {
			entry.Analyst = row[idx]
		}
		if idx, ok := colIdx["timestamp"]; ok && idx < len(row) {
			if t, err := time.Parse(time.RFC3339, row[idx]); err == nil {
				entry.Timestamp = t
			}
		}
		entries = append(entries, entry)
	}
	return entries, nil
}
