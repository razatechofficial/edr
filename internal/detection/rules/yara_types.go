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
