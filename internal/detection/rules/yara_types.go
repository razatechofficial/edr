package rules

// YARAMatch represents a YARA rule match.
type YARAMatch struct {
	Rule      string
	Namespace string
	Tags      []string
	Strings   []YARAString
	Meta      map[string]interface{}
}

// YARAString represents a matched string within a YARA rule.
type YARAString struct {
	Name   string
	Offset uint64
	Data   []byte
}

// YARAScanResult is delivered asynchronously from the YARA worker pool to the detection engine.
type YARAScanResult struct {
	Matches []YARAMatch
	Event   interface{}
	Path    string
}

type scanRequest struct {
	path     string
	data     []byte
	resultCh chan<- []YARAMatch
	event    interface{}
	async    bool
}
