package detection

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"gopkg.in/yaml.v3"

	"github.com/razatechofficial/edr/internal/detection/rules"
)

type BehavioralEngine struct {
	chains  []ChainDefinition
	windows map[string]*ChainWindow
	mu      sync.Mutex
}

type behavioralFile struct {
	Chains []ChainDefinition `yaml:"chains"`
}

type ChainDefinition struct {
	ID            string      `yaml:"id"`
	Name          string      `yaml:"name"`
	Description   string      `yaml:"description"`
	Technique     string      `yaml:"technique"`
	Tactic        string      `yaml:"tactic"`
	Severity      string      `yaml:"severity"`
	Confidence    float64     `yaml:"confidence"`
	WindowSeconds int         `yaml:"window_seconds"`
	Steps         []ChainStep `yaml:"steps"`
}

type ChainStep struct {
	ID             string                 `yaml:"id"`
	EventType      string                 `yaml:"event_type"`
	ParentMatches  string                 `yaml:"parent_matches"`
	SamePID        string                 `yaml:"same_pid"`
	CountThreshold int                    `yaml:"count_threshold"`
	Conditions     map[string]interface{} `yaml:"conditions"`
}

type ChainWindow struct {
	ChainID   string
	HostID    string
	Steps     []interface{}
	LastMatch time.Time
	ExpiresAt time.Time
	StepIndex int
}

func NewBehavioralEngine(path string) (*BehavioralEngine, error) {
	b := &BehavioralEngine{windows: make(map[string]*ChainWindow)}
	if err := b.Reload(path); err != nil {
		return nil, err
	}
	return b, nil
}

func (e *BehavioralEngine) Reload(path string) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var f behavioralFile
	if err := yaml.Unmarshal(b, &f); err != nil {
		return err
	}
	if len(f.Chains) == 0 {
		return fmt.Errorf("no behavioral chains loaded")
	}
	e.mu.Lock()
	e.chains = f.Chains
	e.windows = make(map[string]*ChainWindow)
	e.mu.Unlock()
	return nil
}

func (e *BehavioralEngine) Process(event interface{}) []Detection {
	evm := rules.EventToMap(event)
	if evm == nil {
		return nil
	}
	now := time.Now().UTC()
	hostID := stringField(evm, "endpoint_id", "hostname")
	if hostID == "" {
		hostID = "unknown"
	}
	var out []Detection

	e.mu.Lock()
	defer e.mu.Unlock()
	for key, w := range e.windows {
		if now.After(w.ExpiresAt) {
			delete(e.windows, key)
		}
	}

	for _, c := range e.chains {
		if len(c.Steps) == 0 {
			continue
		}
		wkey := hostID + ":" + c.ID
		w, ok := e.windows[wkey]
		if !ok {
			w = &ChainWindow{
				ChainID:   c.ID,
				HostID:    hostID,
				ExpiresAt: now.Add(time.Duration(c.WindowSeconds) * time.Second),
			}
			e.windows[wkey] = w
		}
		step := c.Steps[w.StepIndex]
		if !eventMatchesType(evm, step.EventType) {
			continue
		}
		if !matchConditions(evm, step.Conditions) {
			continue
		}
		w.Steps = append(w.Steps, event)
		w.LastMatch = now
		w.ExpiresAt = now.Add(time.Duration(c.WindowSeconds) * time.Second)
		w.StepIndex++
		if step.CountThreshold > 0 && len(w.Steps) < step.CountThreshold {
			w.StepIndex--
			continue
		}
		if w.StepIndex >= len(c.Steps) {
			out = append(out, Detection{
				ID:          uuid.New().String(),
				Timestamp:   now,
				RuleID:      c.ID,
				RuleName:    c.Name,
				Severity:    parseSeverity(c.Severity),
				Confidence:  c.Confidence,
				TechniqueID: c.Technique,
				TacticName:  c.Tactic,
				Source:      SourceBehavioral,
				Event:       event,
				Context:     append([]interface{}(nil), w.Steps...),
				Tags:        []string{"behavioral", strings.ToLower(c.Tactic)},
				Description: c.Description,
			})
			delete(e.windows, wkey)
		}
	}
	return out
}

func parseSeverity(s string) Severity {
	switch strings.ToUpper(strings.TrimSpace(s)) {
	case "P0", "CRITICAL":
		return P0
	case "P1", "HIGH":
		return P1
	case "P2", "MEDIUM":
		return P2
	default:
		return P3
	}
}

func eventMatchesType(m map[string]interface{}, want string) bool {
	t := strings.ToLower(stringField(m, "event_type", "type"))
	want = strings.ToLower(want)
	if t == want {
		return true
	}
	switch want {
	case "process_creation":
		return t == "process"
	case "file_event":
		return t == "file"
	case "network_connection":
		return t == "network"
	case "registry_event":
		return t == "registry"
	}
	return false
}

func matchConditions(m map[string]interface{}, cond map[string]interface{}) bool {
	if len(cond) == 0 {
		return true
	}
	for k, v := range cond {
		if strings.Contains(k, "|contains") {
			if !containsAnyList(stringField(m, normalizeCondKey(k)), toStringSlice(v)) {
				return false
			}
			continue
		}
		if strings.Contains(k, "|endswith") {
			if !endsWithAny(stringField(m, normalizeCondKey(k)), toStringSlice(v)) {
				return false
			}
			continue
		}
		got := stringField(m, k)
		expect := toStringSlice(v)
		if len(expect) == 0 {
			continue
		}
		if got != expect[0] {
			return false
		}
	}
	return true
}

func normalizeCondKey(k string) string {
	k = strings.Split(k, "|")[0]
	k = strings.TrimSpace(k)
	return strings.ToLower(k)
}

func stringField(m map[string]interface{}, keys ...string) string {
	for _, k := range keys {
		for fk, fv := range m {
			if strings.EqualFold(fk, k) {
				return fmt.Sprint(fv)
			}
		}
	}
	return ""
}

func toStringSlice(v interface{}) []string {
	switch x := v.(type) {
	case string:
		return []string{x}
	case []interface{}:
		out := make([]string, 0, len(x))
		for _, e := range x {
			out = append(out, fmt.Sprint(e))
		}
		return out
	case []string:
		return x
	default:
		if v == nil {
			return nil
		}
		return []string{fmt.Sprint(v)}
	}
}

func containsAnyList(h string, needles []string) bool {
	h = strings.ToLower(h)
	for _, n := range needles {
		if strings.Contains(h, strings.ToLower(n)) {
			return true
		}
	}
	return false
}

func endsWithAny(h string, needles []string) bool {
	h = strings.ToLower(h)
	for _, n := range needles {
		if strings.HasSuffix(h, strings.ToLower(n)) {
			return true
		}
	}
	return false
}

func atoiDefault(s string, def int) int {
	n, err := strconv.Atoi(strings.TrimSpace(s))
	if err != nil {
		return def
	}
	return n
}
