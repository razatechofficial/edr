package threatintel

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// MISPEvent is a simplified representation of a MISP event.
type MISPEvent struct {
	ID          string          `json:"id"`
	Info        string          `json:"info"`
	Date        string          `json:"date"`
	ThreatLevel string          `json:"threat_level_id"`
	Tags        []MISPTag       `json:"Tag,omitempty"`
	Attributes  []MISPAttribute `json:"Attribute,omitempty"`
}

// MISPAttribute represents a single indicator within a MISP event.
type MISPAttribute struct {
	ID       string    `json:"id"`
	EventID  string    `json:"event_id"`
	Type     string    `json:"type"`
	Category string    `json:"category"`
	Value    string    `json:"value"`
	Comment  string    `json:"comment,omitempty"`
	Tags     []MISPTag `json:"Tag,omitempty"`
}

// MISPTag is a tag attached to an event or attribute.
type MISPTag struct {
	Name string `json:"name"`
}

type mispEventsResponse struct {
	Response []struct {
		Event MISPEvent `json:"Event"`
	} `json:"response"`
}

type mispAttributesResponse struct {
	Response struct {
		Attribute []MISPAttribute `json:"Attribute"`
	} `json:"response"`
}

// MISPClient implements integration with the MISP REST API for threat
// intelligence ingestion.
type MISPClient struct {
	url    string
	apiKey string
	client *http.Client
}

// NewMISPClient creates a MISPClient targeting the given MISP instance.
func NewMISPClient(url, apiKey string, verifySSL bool) *MISPClient {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = &tls.Config{
		InsecureSkipVerify: !verifySSL, //nolint:gosec
	}
	return &MISPClient{
		url:    strings.TrimRight(url, "/"),
		apiKey: apiKey,
		client: &http.Client{
			Timeout:   30 * time.Second,
			Transport: transport,
		},
	}
}

// Name returns the feed identifier.
func (c *MISPClient) Name() string { return "misp" }

// Fetch retrieves indicators published since the given timestamp.
func (c *MISPClient) Fetch(ctx context.Context, since time.Time) ([]Indicator, error) {
	events, err := c.FetchEvents(since)
	if err != nil {
		return nil, err
	}

	var indicators []Indicator
	for _, ev := range events {
		for _, attr := range ev.Attributes {
			ind := attributeToIndicator(attr, ev)
			if ind != nil {
				indicators = append(indicators, *ind)
			}
		}
	}
	return indicators, nil
}

// FetchEvents retrieves MISP events modified since the given timestamp.
func (c *MISPClient) FetchEvents(since time.Time) ([]MISPEvent, error) {
	body := fmt.Sprintf(`{"timestamp":"%d"}`, since.Unix())
	req, err := http.NewRequest(http.MethodPost, c.url+"/events/restSearch", strings.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("misp: build request: %w", err)
	}
	c.setHeaders(req)

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("misp: fetch events: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("misp: unexpected status %d", resp.StatusCode)
	}

	data, err := io.ReadAll(io.LimitReader(resp.Body, 50<<20))
	if err != nil {
		return nil, fmt.Errorf("misp: read response: %w", err)
	}

	var result mispEventsResponse
	if err := json.Unmarshal(data, &result); err != nil {
		return nil, fmt.Errorf("misp: decode events: %w", err)
	}

	events := make([]MISPEvent, 0, len(result.Response))
	for _, r := range result.Response {
		events = append(events, r.Event)
	}
	return events, nil
}

// FetchAttributes retrieves attributes for a specific MISP event.
func (c *MISPClient) FetchAttributes(eventID string) ([]MISPAttribute, error) {
	body := fmt.Sprintf(`{"eventid":"%s"}`, eventID)
	req, err := http.NewRequest(http.MethodPost, c.url+"/attributes/restSearch", strings.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("misp: build request: %w", err)
	}
	c.setHeaders(req)

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("misp: fetch attributes: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("misp: unexpected status %d", resp.StatusCode)
	}

	data, err := io.ReadAll(io.LimitReader(resp.Body, 50<<20))
	if err != nil {
		return nil, fmt.Errorf("misp: read response: %w", err)
	}

	var result mispAttributesResponse
	if err := json.Unmarshal(data, &result); err != nil {
		return nil, fmt.Errorf("misp: decode attributes: %w", err)
	}
	return result.Response.Attribute, nil
}

func (c *MISPClient) setHeaders(req *http.Request) {
	req.Header.Set("Authorization", c.apiKey)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
}

func attributeToIndicator(attr MISPAttribute, ev MISPEvent) *Indicator {
	ind := &Indicator{
		Source: "misp",
	}

	for _, t := range attr.Tags {
		ind.Tags = append(ind.Tags, t.Name)
	}
	for _, t := range ev.Tags {
		ind.Tags = append(ind.Tags, t.Name)
	}

	switch ev.ThreatLevel {
	case "1":
		ind.Severity = "critical"
	case "2":
		ind.Severity = "high"
	case "3":
		ind.Severity = "medium"
	default:
		ind.Severity = "low"
	}

	switch attr.Type {
	case "md5", "sha1", "sha256":
		ind.Type = "hash"
		ind.Value = attr.Value
	case "ip-src", "ip-dst":
		ind.Type = "ip"
		ind.Value = attr.Value
	case "domain", "hostname":
		ind.Type = "domain"
		ind.Value = attr.Value
	default:
		return nil
	}

	return ind
}
