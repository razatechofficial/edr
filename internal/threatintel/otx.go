package threatintel

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"
)

const otxBaseURL = "https://otx.alienvault.com/api/v2"

// OTXPulse represents an AlienVault OTX pulse containing threat indicators.
type OTXPulse struct {
	ID          string         `json:"id"`
	Name        string         `json:"name"`
	Description string         `json:"description"`
	Tags        []string       `json:"tags,omitempty"`
	TLP         string         `json:"tlp,omitempty"`
	Created     string         `json:"created"`
	Modified    string         `json:"modified"`
	Indicators  []OTXIndicator `json:"indicators,omitempty"`
}

// OTXIndicator is a single indicator within an OTX pulse.
type OTXIndicator struct {
	ID        int    `json:"id"`
	Indicator string `json:"indicator"`
	Type      string `json:"type"`
	Title     string `json:"title,omitempty"`
}

type otxPulseResponse struct {
	Results []OTXPulse `json:"results"`
	Next    string     `json:"next"`
	Count   int        `json:"count"`
}

// OTXClient implements integration with the AlienVault OTX API v2.
type OTXClient struct {
	apiKey string
	client *http.Client
}

// NewOTXClient creates an OTXClient with the given API key.
func NewOTXClient(apiKey string) *OTXClient {
	return &OTXClient{
		apiKey: apiKey,
		client: &http.Client{Timeout: 30 * time.Second},
	}
}

// Name returns the feed identifier.
func (c *OTXClient) Name() string { return "otx" }

// Fetch retrieves indicators from pulses modified since the given timestamp.
func (c *OTXClient) Fetch(ctx context.Context, since time.Time) ([]Indicator, error) {
	pulses, err := c.FetchPulses(since)
	if err != nil {
		return nil, err
	}

	var indicators []Indicator
	for _, p := range pulses {
		for _, oi := range p.Indicators {
			ind := otxIndicatorToIndicator(oi, p)
			if ind != nil {
				indicators = append(indicators, *ind)
			}
		}
	}
	return indicators, nil
}

// FetchPulses retrieves OTX pulses modified since the given timestamp.
func (c *OTXClient) FetchPulses(since time.Time) ([]OTXPulse, error) {
	u, _ := url.Parse(otxBaseURL + "/pulses/subscribed")
	q := u.Query()
	q.Set("modified_since", since.Format(time.RFC3339))
	q.Set("limit", "50")
	u.RawQuery = q.Encode()

	var allPulses []OTXPulse
	nextURL := u.String()

	for nextURL != "" {
		req, err := http.NewRequest(http.MethodGet, nextURL, nil)
		if err != nil {
			return nil, fmt.Errorf("otx: build request: %w", err)
		}
		req.Header.Set("X-OTX-API-KEY", c.apiKey)
		req.Header.Set("Accept", "application/json")

		resp, err := c.client.Do(req)
		if err != nil {
			return nil, fmt.Errorf("otx: fetch pulses: %w", err)
		}

		data, err := io.ReadAll(io.LimitReader(resp.Body, 50<<20))
		resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("otx: unexpected status %d", resp.StatusCode)
		}
		if err != nil {
			return nil, fmt.Errorf("otx: read response: %w", err)
		}

		var result otxPulseResponse
		if err := json.Unmarshal(data, &result); err != nil {
			return nil, fmt.Errorf("otx: decode pulses: %w", err)
		}

		allPulses = append(allPulses, result.Results...)
		nextURL = result.Next

		if len(allPulses) > 5000 {
			break
		}
	}

	return allPulses, nil
}

func otxIndicatorToIndicator(oi OTXIndicator, pulse OTXPulse) *Indicator {
	ind := &Indicator{
		Value:  oi.Indicator,
		Source: "otx",
		Tags:   pulse.Tags,
	}

	switch pulse.TLP {
	case "red":
		ind.Severity = "critical"
	case "amber":
		ind.Severity = "high"
	case "green":
		ind.Severity = "medium"
	default:
		ind.Severity = "low"
	}

	switch oi.Type {
	case "FileHash-MD5", "FileHash-SHA1", "FileHash-SHA256":
		ind.Type = "hash"
	case "IPv4", "IPv6":
		ind.Type = "ip"
	case "domain", "hostname":
		ind.Type = "domain"
	default:
		return nil
	}

	return ind
}
