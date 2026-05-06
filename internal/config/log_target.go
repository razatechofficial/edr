package config

import "time"

// LogTarget is a configured log source (monitoring.log_targets).
// Type: file | eventchannel | journald | command | full_command
type LogTarget struct {
	Type     string        `yaml:"type"`
	Path     string        `yaml:"path"`
	Format   string        `yaml:"format"`
	Query    string        `yaml:"query"`
	Interval time.Duration `yaml:"interval"`
}
