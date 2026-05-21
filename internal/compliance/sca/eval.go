package sca

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// EvalConfig controls SCA rule evaluation behavior.
type EvalConfig struct {
	CommandTimeout time.Duration
	CommandsEnabled bool
}

func defaultEvalConfig() EvalConfig {
	return EvalConfig{
		CommandTimeout:  30 * time.Second,
		CommandsEnabled: true,
	}
}

// EvaluatePolicy runs requirements and all checks for one policy.
func EvaluatePolicy(ctx context.Context, p Policy, cfg EvalConfig) ScanSummary {
	if cfg.CommandTimeout <= 0 {
		cfg.CommandTimeout = 30 * time.Second
	}
	summary := ScanSummary{
		PolicyID:   p.Policy.ID,
		PolicyName: p.Policy.Name,
	}
	if p.Requirements != nil && len(p.Requirements.Rules) > 0 {
		ok, err := evaluateCondition(ctx, p.Requirements.Condition, p.Requirements.Rules, cfg)
		if err != nil {
			summary.Skipped = len(p.Checks)
			return summary
		}
		if !ok {
			summary.Skipped = len(p.Checks)
			return summary
		}
	}
	for _, chk := range p.Checks {
		res := evaluateCheck(ctx, p, chk, cfg)
		summary.Results = append(summary.Results, res)
		switch res.Result {
		case "passed":
			summary.Passed++
		case "failed":
			summary.Failed++
		case "error":
			summary.Errors++
		default:
			summary.Skipped++
		}
	}
	return summary
}

func evaluateCheck(ctx context.Context, p Policy, chk Check, cfg EvalConfig) CheckResult {
	res := CheckResult{
		PolicyID:    p.Policy.ID,
		PolicyName:  p.Policy.Name,
		CheckID:     chk.ID,
		Title:       chk.Name,
		Description: chk.Description,
		Remediation: chk.Remediation,
		Compliance:  chk.Compliance,
		MITRE:       chk.MITRE,
	}
	cond := strings.TrimSpace(chk.Condition)
	if cond == "" {
		cond = "all"
	}
	ok, err := evaluateCondition(ctx, cond, chk.Rules, cfg)
	if err != nil {
		res.Result = "error"
		res.Error = err.Error()
		return res
	}
	if ok {
		res.Result = "passed"
	} else {
		res.Result = "failed"
	}
	return res
}

func evaluateCondition(ctx context.Context, condition string, rules []string, cfg EvalConfig) (bool, error) {
	if len(rules) == 0 {
		return true, nil
	}
	cond := strings.ToLower(strings.TrimSpace(condition))
	if cond == "" {
		cond = "all"
	}
	var (
		passes int
		errs   int
	)
	for _, rule := range rules {
		pass, err := evaluateRule(ctx, rule, cfg)
		if err != nil {
			errs++
			if cond == "all" {
				return false, err
			}
			continue
		}
		if pass {
			passes++
		}
	}
	if errs > 0 && cond == "all" {
		return false, fmt.Errorf("sca: %d rule errors in condition %q", errs, condition)
	}
	switch cond {
	case "all":
		return passes == len(rules), nil
	case "any":
		return passes > 0, nil
	case "none":
		return passes == 0, nil
	default:
		return passes == len(rules), nil
	}
}

func evaluateRule(ctx context.Context, raw string, cfg EvalConfig) (bool, error) {
	rule := strings.TrimSpace(raw)
	negated := false
	if strings.HasPrefix(rule, "not ") {
		negated = true
		rule = strings.TrimSpace(rule[4:])
	}
	pass, err := evalRuleBody(ctx, rule, cfg)
	if err != nil {
		return false, err
	}
	if negated {
		return !pass, nil
	}
	return pass, nil
}

func evalRuleBody(ctx context.Context, rule string, cfg EvalConfig) (bool, error) {
	pattern := extractPattern(rule)
	body := ruleBodyWithoutPattern(rule)
	negatedType := false
	if strings.HasPrefix(body, "!") {
		negatedType = true
		body = strings.TrimSpace(body[1:])
	}
	typ, value, err := parseRuleType(body)
	if err != nil {
		return false, err
	}
	var pass bool
	switch typ {
	case "f":
		pass, err = evalFileRule(value, pattern)
	case "c":
		if !cfg.CommandsEnabled {
			return false, fmt.Errorf("sca: commands disabled")
		}
		pass, err = evalCommandRule(ctx, value, pattern, cfg.CommandTimeout)
	case "d":
		pass, err = evalDirRule(value, pattern)
	case "r":
		pass, err = evalRegistryRule(value, pattern)
	case "p":
		return false, fmt.Errorf("sca: process rules not implemented")
	default:
		return false, fmt.Errorf("sca: unknown rule type in %q", rule)
	}
	if err != nil {
		return false, err
	}
	if negatedType {
		pass = !pass
	}
	return pass, nil
}

func parseRuleType(body string) (typ, value string, err error) {
	idx := strings.Index(body, ":")
	if idx <= 0 {
		return "", "", fmt.Errorf("sca: invalid rule %q", body)
	}
	return body[:idx], strings.TrimSpace(body[idx+1:]), nil
}

const ruleSep = " -> "

func extractPattern(rule string) string {
	idx := strings.Index(rule, ruleSep)
	if idx < 0 {
		return ""
	}
	return strings.TrimSpace(rule[idx+len(ruleSep):])
}

func ruleBodyWithoutPattern(rule string) string {
	idx := strings.Index(rule, ruleSep)
	if idx < 0 {
		return strings.TrimSpace(rule)
	}
	return strings.TrimSpace(rule[:idx])
}

func evalFileRule(path, pattern string) (bool, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return false, fmt.Errorf("sca: empty file path")
	}
	b, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		if os.IsNotExist(err) && pattern == "" {
			return false, nil
		}
		if os.IsNotExist(err) {
			return matchContent("", pattern)
		}
		return false, err
	}
	if pattern == "" {
		return true, nil
	}
	return matchContent(string(b), pattern)
}

func evalDirRule(path, pattern string) (bool, error) {
	path = strings.TrimSpace(path)
	entries, err := os.ReadDir(filepath.Clean(path))
	if err != nil {
		return false, err
	}
	if pattern == "" {
		return len(entries) > 0, nil
	}
	var names []string
	for _, e := range entries {
		names = append(names, e.Name())
	}
	return matchContent(strings.Join(names, "\n"), pattern)
}

func evalCommandRule(ctx context.Context, command, pattern string, timeout time.Duration) (bool, error) {
	command = strings.TrimSpace(command)
	if command == "" {
		return false, fmt.Errorf("sca: empty command")
	}
	cctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	parts := splitCommand(command)
	if len(parts) == 0 {
		return false, fmt.Errorf("sca: empty command")
	}
	cmd := exec.CommandContext(cctx, parts[0], parts[1:]...)
	out, err := cmd.CombinedOutput()
	content := string(out)
	if err != nil {
		// Non-zero exit with output is still valid content for pattern match.
		if pattern == "" {
			return false, nil
		}
		return matchContent(content, pattern)
	}
	if pattern == "" {
		return true, nil
	}
	return matchContent(content, pattern)
}

func splitCommand(command string) []string {
	return strings.Fields(command)
}

func matchContent(content, pattern string) (bool, error) {
	pattern = strings.TrimSpace(pattern)
	if pattern == "" {
		return content != "", nil
	}
	if strings.HasPrefix(pattern, "n:") {
		return evalNumericPattern(content, strings.TrimPrefix(pattern, "n:"))
	}
	if strings.HasPrefix(pattern, "r:") {
		re, err := regexp.Compile(strings.TrimPrefix(pattern, "r:"))
		if err != nil {
			return false, fmt.Errorf("sca: regex: %w", err)
		}
		return re.MatchString(content), nil
	}
	return strings.Contains(content, pattern), nil
}

func evalNumericPattern(content, expr string) (bool, error) {
	expr = strings.TrimSpace(expr)
	const cmpWord = "compare"
	idx := strings.Index(expr, cmpWord)
	if idx < 0 {
		return false, fmt.Errorf("sca: numeric pattern missing compare")
	}
	rePart := strings.TrimSpace(expr[:idx])
	rePart = strings.TrimSuffix(rePart, " ")
	rest := strings.TrimSpace(expr[idx+len(cmpWord):])
	fields := strings.Fields(rest)
	if len(fields) < 2 {
		return false, fmt.Errorf("sca: invalid numeric compare")
	}
	op := fields[0]
	want, err := strconv.Atoi(fields[1])
	if err != nil {
		return false, err
	}
	re, err := regexp.Compile(rePart)
	if err != nil {
		return false, err
	}
	m := re.FindStringSubmatch(content)
	if len(m) < 2 {
		return false, nil
	}
	got, err := strconv.Atoi(m[1])
	if err != nil {
		return false, err
	}
	switch op {
	case "<":
		return got < want, nil
	case "<=":
		return got <= want, nil
	case "==":
		return got == want, nil
	case "!=":
		return got != want, nil
	case ">=":
		return got >= want, nil
	case ">":
		return got > want, nil
	default:
		return false, fmt.Errorf("sca: unknown compare op %q", op)
	}
}
