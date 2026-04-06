package threatintel

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// FeedClient is a generic client for STIX, TAXII, CSV, and JSON threat
// intelligence feeds.
type FeedClient struct {
	name   string
	url    string
	format string // stix, taxii, csv, json
	apiKey string
	client *http.Client
}

// NewFeedClient creates a FeedClient for a generic threat intelligence source.
func NewFeedClient(name, url, format, apiKey string) *FeedClient {
	return &FeedClient{
		name:   name,
		url:    url,
		format: strings.ToLower(format),
		apiKey: apiKey,
		client: &http.Client{Timeout: 60 * time.Second},
	}
}

// Name returns the feed identifier.
func (c *FeedClient) Name() string { return c.name }

// Fetch retrieves indicators from the feed.
func (c *FeedClient) Fetch(ctx context.Context, since time.Time) ([]Indicator, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.url, nil)
	if err != nil {
		return nil, fmt.Errorf("feed %s: build request: %w", c.name, err)
	}

	if c.apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+c.apiKey)
	}
	req.Header.Set("Accept", "application/json")

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("feed %s: fetch: %w", c.name, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("feed %s: unexpected status %d", c.name, resp.StatusCode)
	}

	data, err := io.ReadAll(io.LimitReader(resp.Body, 100<<20))
	if err != nil {
		return nil, fmt.Errorf("feed %s: read body: %w", c.name, err)
	}

	switch c.format {
	case "json":
		return c.parseJSON(data)
	case "csv":
		return c.parseCSV(data)
	case "stix":
		return c.parseSTIX(data)
	case "taxii":
		return c.parseSTIX(data)
	default:
		return nil, fmt.Errorf("feed %s: unsupported format %q", c.name, c.format)
	}
}

func (c *FeedClient) parseJSON(data []byte) ([]Indicator, error) {
	var indicators []Indicator
	if err := json.Unmarshal(data, &indicators); err != nil {
		return nil, fmt.Errorf("feed %s: decode json: %w", c.name, err)
	}
	for i := range indicators {
		if indicators[i].Source == "" {
			indicators[i].Source = c.name
		}
	}
	return indicators, nil
}

func (c *FeedClient) parseCSV(data []byte) ([]Indicator, error) {
	reader := csv.NewReader(strings.NewReader(string(data)))
	reader.TrimLeadingSpace = true
	reader.Comment = '#'

	header, err := reader.Read()
	if err != nil {
		return nil, fmt.Errorf("feed %s: read csv header: %w", c.name, err)
	}

	colIndex := make(map[string]int)
	for i, h := range header {
		colIndex[strings.ToLower(strings.TrimSpace(h))] = i
	}

	var indicators []Indicator
	for {
		record, err := reader.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("feed %s: read csv row: %w", c.name, err)
		}

		ind := Indicator{Source: c.name}
		if idx, ok := colIndex["indicator"]; ok && idx < len(record) {
			ind.Value = record[idx]
		} else if idx, ok := colIndex["value"]; ok && idx < len(record) {
			ind.Value = record[idx]
		} else if len(record) > 0 {
			ind.Value = record[0]
		}

		if idx, ok := colIndex["type"]; ok && idx < len(record) {
			ind.Type = record[idx]
		}
		if idx, ok := colIndex["severity"]; ok && idx < len(record) {
			ind.Severity = record[idx]
		}
		if idx, ok := colIndex["tags"]; ok && idx < len(record) && record[idx] != "" {
			ind.Tags = strings.Split(record[idx], ";")
		}

		if ind.Value != "" {
			if ind.Type == "" {
				ind.Type = guessIndicatorType(ind.Value)
			}
			indicators = append(indicators, ind)
		}
	}
	return indicators, nil
}

type stixBundle struct {
	Objects []stixObject `json:"objects"`
}

type stixObject struct {
	Type    string `json:"type"`
	Pattern string `json:"pattern,omitempty"`
	Labels  []string `json:"labels,omitempty"`
	Name    string `json:"name,omitempty"`
}

func (c *FeedClient) parseSTIX(data []byte) ([]Indicator, error) {
	var bundle stixBundle
	if err := json.Unmarshal(data, &bundle); err != nil {
		return nil, fmt.Errorf("feed %s: decode stix: %w", c.name, err)
	}

	var indicators []Indicator
	for _, obj := range bundle.Objects {
		if obj.Type != "indicator" {
			continue
		}
		ind := extractSTIXIndicator(obj)
		if ind == nil {
			continue
		}
		ind.Source = c.name
		ind.Tags = obj.Labels
		indicators = append(indicators, *ind)
	}
	return indicators, nil
}

func extractSTIXIndicator(obj stixObject) *Indicator {
	pattern := obj.Pattern
	ind := &Indicator{Severity: "medium"}

	switch {
	case strings.Contains(pattern, "file:hashes"):
		ind.Type = "hash"
		ind.Value = extractSTIXValue(pattern)
	case strings.Contains(pattern, "ipv4-addr:value") || strings.Contains(pattern, "ipv6-addr:value"):
		ind.Type = "ip"
		ind.Value = extractSTIXValue(pattern)
	case strings.Contains(pattern, "domain-name:value"):
		ind.Type = "domain"
		ind.Value = extractSTIXValue(pattern)
	default:
		return nil
	}

	if ind.Value == "" {
		return nil
	}
	return ind
}

func extractSTIXValue(pattern string) string {
	start := strings.Index(pattern, "'")
	if start < 0 {
		return ""
	}
	end := strings.Index(pattern[start+1:], "'")
	if end < 0 {
		return ""
	}
	return pattern[start+1 : start+1+end]
}

func guessIndicatorType(value string) string {
	switch {
	case len(value) == 32 || len(value) == 40 || len(value) == 64:
		return "hash"
	case strings.Count(value, ".") == 3 && !strings.Contains(value, "/"):
		return "ip"
	case strings.Contains(value, ".") && !strings.Contains(value, "/"):
		return "domain"
	default:
		return "unknown"
	}
}
