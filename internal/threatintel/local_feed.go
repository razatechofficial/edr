package threatintel

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"
)

// LocalFeed reads indicators from a file on disk (airgap / sneakernet updates).
type LocalFeed struct {
	name   string
	path   string
	format string
	client *FeedClient
}

// NewLocalFeed creates a feed backed by a local JSON, CSV, or STIX file.
func NewLocalFeed(name, path, format string) *LocalFeed {
	path = strings.TrimSpace(path)
	format = strings.ToLower(strings.TrimSpace(format))
	if format == "" {
		switch {
		case strings.HasSuffix(path, ".csv"):
			format = "csv"
		default:
			format = "json"
		}
	}
	return &LocalFeed{
		name:   name,
		path:   path,
		format: format,
		client: NewFeedClient(name, "", format, ""),
	}
}

func (f *LocalFeed) Name() string { return f.name }

func (f *LocalFeed) Fetch(_ context.Context, _ time.Time) ([]Indicator, error) {
	data, err := os.ReadFile(f.path)
	if err != nil {
		return nil, fmt.Errorf("local feed %s: read %s: %w", f.name, f.path, err)
	}
	switch f.format {
	case "json":
		return f.client.parseJSON(data)
	case "csv":
		return f.client.parseCSV(data)
	case "stix", "taxii":
		return f.client.parseSTIX(data)
	default:
		return nil, fmt.Errorf("local feed %s: unsupported format %q", f.name, f.format)
	}
}
