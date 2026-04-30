package rules

import "time"

// YARAEngineOptions tunes scan pacing and exclusions (present in stub and CGO builds).
type YARAEngineOptions struct {
	RescanCooldown  time.Duration
	MaxScansPerMin  int
	ExcludePrefixes []string
}

// YARAString is one matched string instance from a rule.
type YARAString struct {
	Name   string
	Offset uint64
	Data   []byte
}

// YARAMatch is a single rule match result (CGO path fills from go-yara).
type YARAMatch struct {
	Rule      string
	Namespace string
	Tags      []string
	Strings   []YARAString
	Meta      map[string]interface{}
}

// YARAScanResult is emitted on the async sink after a background scan.
type YARAScanResult struct {
	Matches []YARAMatch
	Path    string
	Event   interface{}
}

// scanRequest is an internal work item for the YARA worker pool.
type scanRequest struct {
	path     string
	data     []byte
	event    interface{}
	async    bool
	resultCh chan []YARAMatch
}
