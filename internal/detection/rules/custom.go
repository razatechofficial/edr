package rules

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/google/cel-go/cel"
	"github.com/google/uuid"
	"go.uber.org/zap"
	"gopkg.in/yaml.v3"

	"github.com/razatechofficial/edr/pkg/events"
)

// CustomRule defines a CEL-based detection rule.
type CustomRule struct {
	ID          string               `yaml:"id" json:"id"`
	Name        string               `yaml:"name" json:"name"`
	Description string               `yaml:"description" json:"description"`
	Severity    string               `yaml:"severity" json:"severity"`
	Expression  string               `yaml:"expression" json:"expression"`
	MITRE       []events.MITREAttack `yaml:"mitre" json:"mitre"`
	Tags        []string             `yaml:"tags" json:"tags"`
	Enabled     bool                 `yaml:"enabled" json:"enabled"`
}

// CustomEngine evaluates events against CEL-based custom rules.
type CustomEngine struct {
	env    *cel.Env
	rules  []compiledRule
	mu     sync.RWMutex
	logger *zap.Logger
}

type compiledRule struct {
	def     CustomRule
	program cel.Program
}

type customRulesFile struct {
	Rules []CustomRule `yaml:"rules"`
}

// NewCustomEngine creates a CEL environment with EDR-specific variables
// declared and ready for rule compilation.
func NewCustomEngine(logger *zap.Logger) (*CustomEngine, error) {
	env, err := cel.NewEnv(
		cel.Variable("event_type", cel.StringType),
		cel.Variable("process_name", cel.StringType),
		cel.Variable("process_path", cel.StringType),
		cel.Variable("command_line", cel.StringType),
		cel.Variable("pid", cel.IntType),
		cel.Variable("ppid", cel.IntType),
		cel.Variable("parent_name", cel.StringType),
		cel.Variable("user", cel.StringType),
		cel.Variable("file_path", cel.StringType),
		cel.Variable("file_operation", cel.StringType),
		cel.Variable("file_hash", cel.StringType),
		cel.Variable("source_ip", cel.StringType),
		cel.Variable("dest_ip", cel.StringType),
		cel.Variable("source_port", cel.IntType),
		cel.Variable("dest_port", cel.IntType),
		cel.Variable("protocol", cel.StringType),
		cel.Variable("domain", cel.StringType),
		cel.Variable("auth_type", cel.StringType),
		cel.Variable("auth_outcome", cel.StringType),
		cel.Variable("hostname", cel.StringType),
		cel.Variable("os", cel.StringType),
		cel.Variable("severity", cel.StringType),
	)
	if err != nil {
		return nil, fmt.Errorf("cel: create environment: %w", err)
	}

	return &CustomEngine{
		env:    env,
		logger: logger,
	}, nil
}

// LoadRules reads a YAML file or directory of .yaml/.yml files containing
// custom detection rules, compiles each CEL expression, and stores the
// resulting programs for evaluation.
func (e *CustomEngine) LoadRules(path string) error {
	fi, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("cel: rules path: %w", err)
	}
	var compiled []compiledRule
	if fi.IsDir() {
		compiled, err = e.loadRulesFromDir(path)
		if err != nil {
			return err
		}
	} else {
		compiled, err = e.loadRulesFromFile(path)
		if err != nil {
			return err
		}
	}

	e.mu.Lock()
	e.rules = compiled
	e.mu.Unlock()

	e.logger.Info("cel: rules loaded", zap.Int("count", len(compiled)))
	return nil
}

func (e *CustomEngine) loadRulesFromFile(path string) ([]compiledRule, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("cel: read rules: %w", err)
	}
	return e.compileRulesYAML(data, path)
}

func (e *CustomEngine) loadRulesFromDir(dir string) ([]compiledRule, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("cel: read rules dir: %w", err)
	}
	var paths []string
	for _, ent := range entries {
		if ent.IsDir() {
			continue
		}
		ext := strings.ToLower(filepath.Ext(ent.Name()))
		if ext != ".yaml" && ext != ".yml" {
			continue
		}
		paths = append(paths, filepath.Join(dir, ent.Name()))
	}
	sort.Strings(paths)

	var merged []compiledRule
	for _, p := range paths {
		data, err := os.ReadFile(p)
		if err != nil {
			return nil, fmt.Errorf("cel: read rules %q: %w", p, err)
		}
		part, err := e.compileRulesYAML(data, p)
		if err != nil {
			return nil, err
		}
		merged = append(merged, part...)
	}
	return merged, nil
}

func (e *CustomEngine) compileRulesYAML(data []byte, source string) ([]compiledRule, error) {
	var file customRulesFile
	if err := yaml.Unmarshal(data, &file); err != nil {
		return nil, fmt.Errorf("cel: parse rules %q: %w", source, err)
	}

	compiled := make([]compiledRule, 0, len(file.Rules))
	for _, r := range file.Rules {
		if !r.Enabled {
			continue
		}
		prg, err := e.compile(r.Expression)
		if err != nil {
			e.logger.Warn("cel: skipping rule with compile error",
				zap.String("source", source),
				zap.String("rule_id", r.ID),
				zap.Error(err),
			)
			continue
		}
		compiled = append(compiled, compiledRule{def: r, program: prg})
	}
	return compiled, nil
}

// AddRule dynamically compiles and adds a single rule at runtime.
func (e *CustomEngine) AddRule(rule CustomRule) error {
	if !rule.Enabled {
		return fmt.Errorf("cel: rule %s is disabled", rule.ID)
	}
	prg, err := e.compile(rule.Expression)
	if err != nil {
		return fmt.Errorf("cel: compile rule %s: %w", rule.ID, err)
	}

	e.mu.Lock()
	e.rules = append(e.rules, compiledRule{def: rule, program: prg})
	e.mu.Unlock()
	return nil
}

// Evaluate runs all enabled rules against the supplied variable map and
// returns alerts for every rule that matches.
func (e *CustomEngine) Evaluate(vars map[string]interface{}) []*events.Alert {
	e.mu.RLock()
	snapshot := e.rules
	e.mu.RUnlock()

	activation := e.fillDefaults(vars)

	var alerts []*events.Alert
	for _, cr := range snapshot {
		out, _, err := cr.program.Eval(activation)
		if err != nil {
			e.logger.Debug("cel: eval error",
				zap.String("rule_id", cr.def.ID),
				zap.Error(err),
			)
			continue
		}
		matched, ok := out.Value().(bool)
		if !ok || !matched {
			continue
		}

		alert := &events.Alert{
			ID:          uuid.New().String(),
			RuleID:      cr.def.ID,
			RuleName:    cr.def.Name,
			Severity:    events.Severity(cr.def.Severity),
			Title:       cr.def.Name,
			Description: cr.def.Description,
			Timestamp:   time.Now().UTC(),
			MITRE:       cr.def.MITRE,
			Tags:        cr.def.Tags,
			RawEvent:    vars,
		}
		alerts = append(alerts, alert)
	}
	return alerts
}

// Count returns the number of compiled rules.
func (e *CustomEngine) Count() int {
	e.mu.RLock()
	n := len(e.rules)
	e.mu.RUnlock()
	return n
}

func (e *CustomEngine) compile(expr string) (cel.Program, error) {
	ast, iss := e.env.Compile(expr)
	if iss != nil && iss.Err() != nil {
		return nil, iss.Err()
	}
	return e.env.Program(ast)
}

// fillDefaults ensures every declared variable has a value so CEL evaluation
// does not fail on missing keys. Unset strings default to "" and ints to 0.
func (e *CustomEngine) fillDefaults(vars map[string]interface{}) map[string]interface{} {
	defaults := map[string]interface{}{
		"event_type":     "",
		"process_name":   "",
		"process_path":   "",
		"command_line":   "",
		"pid":            int64(0),
		"ppid":           int64(0),
		"parent_name":    "",
		"user":           "",
		"file_path":      "",
		"file_operation": "",
		"file_hash":      "",
		"source_ip":      "",
		"dest_ip":        "",
		"source_port":    int64(0),
		"dest_port":      int64(0),
		"protocol":       "",
		"domain":         "",
		"auth_type":      "",
		"auth_outcome":   "",
		"hostname":       "",
		"os":             "",
		"severity":       "",
	}

	for k, v := range vars {
		defaults[k] = v
	}
	return defaults
}
