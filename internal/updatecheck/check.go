// Package updatecheck implements an enterprise catalog poll for EDR Agent.
//
// Pattern (Jamf / Intune / WSUS / Falcon sensor update, not consumer Sparkle
// auto-install): the agent reports version, a signed JSON catalog names the
// latest build, and an administrator (or MDM) performs the install. Air-gapped
// hosts skip the poll when no catalog URL is configured.
package updatecheck

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// Catalog is the on-wire update index (HTTPS JSON).
type Catalog struct {
	Product       string            `json:"product"`
	Latest        string            `json:"latest"`
	MinSupported  string            `json:"min_supported,omitempty"`
	Released      string            `json:"released,omitempty"`
	NotesURL      string            `json:"notes_url,omitempty"`
	Mandatory     bool              `json:"mandatory,omitempty"`
	Packages      map[string]Package `json:"packages,omitempty"`
}

// Package is one OS/arch artifact.
type Package struct {
	URL    string `json:"url"`
	SHA256 string `json:"sha256,omitempty"`
	Size   int64  `json:"size,omitempty"`
}

// Result is what the console and edrctl show.
type Result struct {
	Current     string `json:"current"`
	Latest      string `json:"latest,omitempty"`
	Update      bool   `json:"update"`
	Mandatory   bool   `json:"mandatory,omitempty"`
	NotesURL    string `json:"notes_url,omitempty"`
	Skipped     string `json:"skipped,omitempty"`
	Error       string `json:"error,omitempty"`
}

// Check fetches catalogURL and compares current (semver-ish). Empty URL skips.
func Check(current, catalogURL string, client *http.Client) Result {
	current = strings.TrimSpace(current)
	if current == "" {
		current = "dev"
	}
	u := strings.TrimSpace(catalogURL)
	if u == "" {
		return Result{Current: current, Skipped: "no catalog URL (MDM/air-gap owns updates)"}
	}
	if client == nil {
		client = &http.Client{Timeout: 8 * time.Second}
	}
	resp, err := client.Get(u)
	if err != nil {
		return Result{Current: current, Error: err.Error()}
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return Result{Current: current, Error: fmt.Sprintf("catalog HTTP %d", resp.StatusCode)}
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return Result{Current: current, Error: err.Error()}
	}
	var cat Catalog
	if err := json.Unmarshal(body, &cat); err != nil {
		return Result{Current: current, Error: "catalog is not valid JSON"}
	}
	latest := strings.TrimSpace(cat.Latest)
	r := Result{
		Current:   current,
		Latest:    latest,
		Mandatory: cat.Mandatory,
		NotesURL:  cat.NotesURL,
	}
	if latest == "" {
		r.Error = "catalog missing latest"
		return r
	}
	cmp, err := compareVersion(current, latest)
	if err != nil {
		// Non-semver (git describe): treat unequal as update available.
		r.Update = current != latest && current != "dev"
		return r
	}
	r.Update = cmp < 0
	return r
}

// Compare returns -1 if a<b, 0 if equal, 1 if a>b.
// Non-semver strings (git describe) compare equal only when identical.
func Compare(a, b string) int {
	n, err := compareVersion(a, b)
	if err != nil {
		a, b = strings.TrimSpace(a), strings.TrimSpace(b)
		switch {
		case a == b:
			return 0
		case a == "" || b == "":
			return 0
		default:
			return -1
		}
	}
	return n
}

// compareVersion returns -1 if a<b, 0 if equal, 1 if a>b. Accepts 1.2.3 or v1.2.3.
func compareVersion(a, b string) (int, error) {
	pa, err := parseVersion(a)
	if err != nil {
		return 0, err
	}
	pb, err := parseVersion(b)
	if err != nil {
		return 0, err
	}
	n := len(pa)
	if len(pb) > n {
		n = len(pb)
	}
	for i := 0; i < n; i++ {
		var va, vb int
		if i < len(pa) {
			va = pa[i]
		}
		if i < len(pb) {
			vb = pb[i]
		}
		if va < vb {
			return -1, nil
		}
		if va > vb {
			return 1, nil
		}
	}
	return 0, nil
}

func parseVersion(s string) ([]int, error) {
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(s, "v")
	s = strings.TrimPrefix(s, "V")
	if i := strings.IndexAny(s, "-+"); i >= 0 {
		s = s[:i]
	}
	parts := strings.Split(s, ".")
	if len(parts) == 0 || parts[0] == "" {
		return nil, fmt.Errorf("empty version")
	}
	out := make([]int, 0, len(parts))
	for _, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil {
			return nil, err
		}
		out = append(out, n)
	}
	return out, nil
}
