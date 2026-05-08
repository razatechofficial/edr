package collector

import (
	"encoding/csv"
	"strings"
)

// MergeWMIPsCSVBlocks concatenates PowerShell ConvertTo-Csv fragments (possibly
// multiple header+body blocks) into a single newline-delimited stream for CSV parsing.
func MergeWMIPsCSVBlocks(s string) string {
	return strings.TrimSpace(s)
}

// ParseWMICsvKV parses one CSV row (comma-separated, quoted fields OK) against an
// expected header row and returns column->value for non-empty headers.
func ParseWMICsvKV(headerLine, dataLine string) (map[string]string, error) {
	r := csv.NewReader(strings.NewReader(headerLine + "\n" + dataLine))
	r.LazyQuotes = true
	rows, err := r.ReadAll()
	if err != nil || len(rows) < 2 {
		return nil, err
	}
	h, d := rows[0], rows[1]
	out := make(map[string]string, len(h))
	for i := range h {
		key := strings.TrimSpace(h[i])
		if key == "" {
			continue
		}
		if i < len(d) {
			out[key] = d[i]
		}
	}
	return out, nil
}
