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
	ID       string `yaml:"id"`
	Name     string `yaml:"name"`
	Severity string `yaml:"severity"`
	When     struct {
		ParentIn            []string `yaml:"parent_in"`
		ChildIn             []string `yaml:"child_in"`
		ProcessPathContains []string `yaml:"process_path_contains"`
		CommandLineContains []string `yaml:"command_line_contains"`
		CommandLineAll      []string `yaml:"command_line_all_contains"`
	} `yaml:"when"`
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
