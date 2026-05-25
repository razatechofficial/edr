package sca

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"gopkg.in/yaml.v3"
)

// Policy is an SCA policy document (CIS-style YAML checks).
type Policy struct {
	Policy       PolicyMeta     `yaml:"policy"`
	Requirements *Requirements  `yaml:"requirements,omitempty"`
	Checks       []Check        `yaml:"checks"`
	sourcePath   string
}

type PolicyMeta struct {
	ID          string   `yaml:"id"`
	File        string   `yaml:"file"`
	Name        string   `yaml:"name"`
	Description string   `yaml:"description"`
	References  []string `yaml:"references,omitempty"`
}

type Requirements struct {
	Name        string   `yaml:"name,omitempty"`
	Description string   `yaml:"description,omitempty"`
	Condition   string   `yaml:"condition"`
	Rules       []string `yaml:"rules"`
}

type Check struct {
	ID          int                `yaml:"id"`
	Name        string             `yaml:"name"`
	Description string             `yaml:"description,omitempty"`
	Rationale   string             `yaml:"rationale,omitempty"`
	Remediation string             `yaml:"remediation,omitempty"`
	Condition   string             `yaml:"condition"`
	Rules       []string           `yaml:"rules"`
	Compliance  map[string][]string `yaml:"compliance,omitempty"`
	MITRE       map[string][]string `yaml:"mitre,omitempty"`
}

// CheckResult is the outcome of evaluating one SCA check.
type CheckResult struct {
	PolicyID    string
	PolicyName  string
	CheckID     int
	Title       string
	Description string
	Remediation string
	Result      string // passed|failed|not_applicable|error
	Compliance  map[string][]string
	MITRE       map[string][]string
	Error       string
}

// ScanSummary aggregates one policy scan.
type ScanSummary struct {
	PolicyID   string
	PolicyName string
	Passed     int
	Failed     int
	Skipped    int
	Errors     int
	Results    []CheckResult
}

// LoadPolicies reads all .yml/.yaml files from the OS-specific SCA directory.
func LoadPolicies(rulesDir string) ([]Policy, error) {
	osDir, err := scaOSDir(rulesDir)
	if err != nil {
		return nil, err
	}
	info, err := os.Stat(osDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("sca: no policies for %s under %q", runtime.GOOS, rulesDir)
		}
		return nil, err
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("sca: %q is not a directory", osDir)
	}
	entries, err := os.ReadDir(osDir)
	if err != nil {
		return nil, err
	}
	var out []Policy
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		ext := strings.ToLower(filepath.Ext(e.Name()))
		if ext != ".yml" && ext != ".yaml" {
			continue
		}
		path := filepath.Join(osDir, e.Name())
		p, err := loadPolicyFile(path)
		if err != nil {
			return nil, fmt.Errorf("sca: %s: %w", path, err)
		}
		out = append(out, p)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("sca: no policy files in %q", osDir)
	}
	return out, nil
}

func scaOSDir(rulesDir string) (string, error) {
	switch runtime.GOOS {
	case "linux":
		return filepath.Join(rulesDir, "linux"), nil
	case "windows":
		return filepath.Join(rulesDir, "windows"), nil
	case "darwin":
		return filepath.Join(rulesDir, "darwin"), nil
	default:
		return "", fmt.Errorf("sca: unsupported os %q", runtime.GOOS)
	}
}

func loadPolicyFile(path string) (Policy, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return Policy{}, err
	}
	b = sanitizeSCAYAML(b)
	var p Policy
	if err := yaml.Unmarshal(b, &p); err != nil {
		return Policy{}, err
	}
	p.sourcePath = path
	if p.Policy.ID == "" {
		p.Policy.ID = strings.TrimSuffix(filepath.Base(path), filepath.Ext(path))
	}
	return p, nil
}

// sanitizeSCAYAML fixes common Wazuh/CIS export escapes that yaml.v3 rejects in
// double-quoted scalars (e.g. \/etc\/audit -> /etc/audit).
func sanitizeSCAYAML(b []byte) []byte {
	if !bytes.Contains(b, []byte(`\/`)) {
		return b
	}
	return bytes.ReplaceAll(b, []byte(`\/`), []byte(`/`))
}
