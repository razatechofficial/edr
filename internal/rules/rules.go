package rules

import (
	"os"

	"gopkg.in/yaml.v3"
)

type RuleSet struct {
	Version string `yaml:"version"`
	Rules   []Rule `yaml:"rules"`
}

type Rule struct {
	ID          string    `yaml:"id"`
	Name        string    `yaml:"name"`
	Severity    string    `yaml:"severity"`
	Score       int       `yaml:"score,omitempty"`
	Description string    `yaml:"description,omitempty"`
	EventType   string    `yaml:"event_type,omitempty"`
	When        Condition `yaml:"when"`
}

type Condition struct {
	// Process conditions
	ParentIn            []string `yaml:"parent_in,omitempty"`
	ChildIn             []string `yaml:"child_in,omitempty"`
	ProcessPathContains []string `yaml:"process_path_contains,omitempty"`
	CommandLineContains []string `yaml:"command_line_contains,omitempty"`
	CommandLineAll      []string `yaml:"command_line_all_contains,omitempty"`

	// File conditions
	FilePathContains []string `yaml:"file_path_contains,omitempty"`
	OperationIn      []string `yaml:"operation_in,omitempty"`

	// Network conditions
	DestIPContains  []string `yaml:"dest_ip_contains,omitempty"`
	DestPortIn      []int    `yaml:"dest_port_in,omitempty"`
	ProtocolIn      []string `yaml:"protocol_in,omitempty"`
	DomainContains  []string `yaml:"domain_contains,omitempty"`
	SourcePtRange   []int    `yaml:"source_port_range,omitempty"`

	// Auth conditions
	SrcUserContains []string `yaml:"src_user_contains,omitempty"`
	OutcomeIn       []string `yaml:"outcome_in,omitempty"`
	AuthTypeIn      []string `yaml:"auth_type_in,omitempty"`
	SourceIPContains []string `yaml:"source_ip_contains,omitempty"`
}

func Load(path string) (RuleSet, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return RuleSet{}, err
	}
	var rs RuleSet
	if err := yaml.Unmarshal(b, &rs); err != nil {
		return RuleSet{}, err
	}
	return rs, nil
}
