package response

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/razatechofficial/edr/internal/detection"
	"go.uber.org/zap"
	"gopkg.in/yaml.v3"
)

// playbooksFile is the root of rules/playbooks/playbooks.yml
type playbooksFile struct {
	Playbooks []PlaybookDef `yaml:"playbooks"`
}

// PlaybookDef is a single YAML playbook (name differs from the legacy [Playbook] interface in engine.go).
type PlaybookDef struct {
	ID                     string `yaml:"id"`
	Name                   string `yaml:"name"`
	Triggers               []Trigger
	ApprovalRequired       bool `yaml:"approval_required"`
	ApprovalTimeoutSeconds int  `yaml:"approval_timeout_seconds"`
	Actions                []PAction
}

// Trigger matches detections; fields are optional.
type Trigger struct {
	Technique     string   `yaml:"technique"`
	MinSeverity   string   `yaml:"min_severity"`
	MinConfidence *float64 `yaml:"min_confidence"`
	MaxConfidence *float64 `yaml:"max_confidence"`
	Source        string   `yaml:"source"`
	Namespace     string   `yaml:"namespace"`
}

// PAction is a playbook action step.
type PAction struct {
	Type   string                 `yaml:"action"`
	Params map[string]interface{} `yaml:"params"`
}

// PlaybookEngine runs YAML playbooks.
type PlaybookEngine struct {
	playbooks []PlaybookDef
	actions   ActionExecutor
	approvals ApprovalGateway
	agentIP   string
	quarDir   string
	logger    *zap.Logger
}

// ActionExecutor runs a resolved op string and params.
type ActionExecutor interface {
	Execute(ctx context.Context, op string, params map[string]interface{}, d detection.Detection) error
}

// NewPlaybookEngineFromFile loads playbooks and wires executor + approval.
func NewPlaybookEngineFromFile(
	path string,
	exec ActionExecutor,
	gw ApprovalGateway,
	agentIP, quarantineDir string,
	log *zap.Logger,
) (*PlaybookEngine, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("playbooks: read %q: %w", path, err)
	}
	var f playbooksFile
	if err := yaml.Unmarshal(b, &f); err != nil {
		return nil, err
	}
	if log == nil {
		log = zap.NewNop()
	}
	if gw == nil {
		gw = &AutoApprovalGateway{}
	}
	return &PlaybookEngine{
		playbooks: f.Playbooks,
		actions:   exec,
		approvals: gw,
		agentIP:   agentIP,
		quarDir:   quarantineDir,
		logger:    log,
	}, nil
}

// selectPlaybook returns the best matching playbook for a detection.
func (e *PlaybookEngine) selectPlaybook(d detection.Detection) *PlaybookDef {
	var best *PlaybookDef
	bestScore := -1
	for i := range e.playbooks {
		p := &e.playbooks[i]
		for _, tr := range p.Triggers {
			if matchTrigger(&tr, d) {
				s := scoreTrigger(&tr, d, p)
				if s > bestScore {
					bestScore = s
					best = p
				}
			}
		}
	}
	return best
}

func matchTrigger(t *Trigger, d detection.Detection) bool {
	if t.Technique != "" && t.Technique != d.TechniqueID {
		return false
	}
	if t.MinSeverity != "" {
		ms, err := ParseSeverityYAML(t.MinSeverity)
		if err == nil {
			// d must be "at most" that severity (numerically, lower index = more severe in our model)
			if d.Severity > ms {
				return false
			}
		}
	}
	if t.MaxConfidence != nil && d.Confidence > *t.MaxConfidence {
		return false
	}
	if t.MinConfidence != nil && d.Confidence < *t.MinConfidence {
		return false
	}
	if t.Source == "yara" {
		if d.Source != detection.SourceYARA {
			return false
		}
		if t.Namespace != "" {
			if !yaraHasNamespace(d, t.Namespace) {
				return false
			}
		}
	}
	if t.Source == "sigma" {
		if d.Source != detection.SourceSigma {
			return false
		}
	}
	if t.Source == "behavioral" {
		if d.Source != detection.SourceBehavioral {
			return false
		}
	}
	return true
}

func yaraHasNamespace(d detection.Detection, ns string) bool {
	if strings.HasPrefix(d.RuleName, ns+":") || strings.Contains(d.RuleName, "/"+ns+"/") {
		return true
	}
	prefix := "namespace=" + ns
	for _, t := range d.Tags {
		if t == ns || t == prefix || strings.Contains(t, ns) {
			return true
		}
	}
	return d.RuleName != "" && strings.Contains(d.RuleName, ns)
}

func scoreTrigger(t *Trigger, d detection.Detection, _ *PlaybookDef) int {
	score := 0
	if t.Technique != "" && t.Technique == d.TechniqueID {
		score += 1000
	} else if t.Technique == "" {
		score += 1
	}
	if t.MinSeverity == "P0" {
		score += 200
	} else if t.MinSeverity == "P1" {
		score += 100
	}
	if t.Source == "yara" && t.Namespace != "" {
		score += 50
	}
	return score
}

// Handle selects and runs a playbook.
func (e *PlaybookEngine) Handle(ctx context.Context, d detection.Detection) error {
	pb := e.selectPlaybook(d)
	if pb == nil {
		return nil
	}
	if pb.ApprovalRequired {
		py := PlaybookYAML{ID: pb.ID, Name: pb.Name, ApprovalRequired: true, ApprovalTimeoutSec: pb.ApprovalTimeoutSeconds}
		approved, err := e.approvals.RequestApproval(ctx, d, py)
		if err != nil {
			return err
		}
		if !approved {
			return nil
		}
	}
	for _, act := range pb.Actions {
		res := e.resolveAction(act, d)
		if err := func() (err error) {
			defer func() {
				if r := recover(); r != nil {
					e.logger.Error("playbook action panicked", zap.String("playbook", pb.ID), zap.String("action", act.Type), zap.Any("recovered", r))
					err = nil
				}
			}()
			return e.actions.Execute(ctx, res.Type, res.Params, d)
		}(); err != nil {
			e.logger.Error("playbook action failed", zap.String("playbook", pb.ID), zap.String("action", act.Type), zap.Error(err))
		}
	}
	return nil
}

type resolvedAction struct {
	Type   string
	Params map[string]interface{}
}

func (e *PlaybookEngine) resolveAction(act PAction, d detection.Detection) resolvedAction {
	return resolvedAction{Type: act.Type, Params: e.resolveMap(act.Params, d)}
}

func (e *PlaybookEngine) resolveMap(in map[string]interface{}, d detection.Detection) map[string]interface{} {
	if in == nil {
		return nil
	}
	out := make(map[string]interface{}, len(in))
	for k, v := range in {
		out[k] = e.resolveValue(v, d)
	}
	return out
}

// resolveValue walks string templates and collections.
func (e *PlaybookEngine) resolveValue(v interface{}, d detection.Detection) interface{} {
	switch t := v.(type) {
	case string:
		return e.subst(t, d)
	case []interface{}:
		rr := make([]interface{}, len(t))
		for i := range t {
			rr[i] = e.resolveValue(t[i], d)
		}
		return rr
	case []string:
		rr := make([]string, len(t))
		for i := range t {
			if s, ok := e.resolveValue(t[i], d).(string); ok {
				rr[i] = s
			}
		}
		return rr
	case map[string]interface{}:
		return e.resolveMap(t, d)
	default:
		return v
	}
}

var tmplVar = regexp.MustCompile(`\{\{([^}]+)\}\}`)

func (e *PlaybookEngine) subst(s string, d detection.Detection) string {
	if !strings.Contains(s, "{{") {
		return s
	}
	return tmplVar.ReplaceAllStringFunc(s, func(full string) string {
		sub := tmplVar.FindStringSubmatch(full)
		if len(sub) < 2 {
			return ""
		}
		key := strings.TrimSpace(sub[1])
		val, ok := lookupEventVar(key, d, e.agentIP, e.quarDir, e.logger)
		if !ok {
			if e.logger != nil {
				e.logger.Warn("unresolved playbook variable", zap.String("var", full))
			}
			return ""
		}
		return val
	})
}

func lookupEventVar(key string, d detection.Detection, agentIP, quarantineDir string, _ *zap.Logger) (string, bool) {
	if key == "agent_ip" {
		if agentIP != "" {
			return agentIP, true
		}
		return "127.0.0.1", true
	}
	if key == "quarantine_dir" {
		if quarantineDir == "" {
			return "", true
		}
		abs, err := filepath.Abs(quarantineDir)
		if err != nil {
			return quarantineDir, true
		}
		return abs, true
	}
	if !strings.HasPrefix(key, "detection.event.") {
		return "", false
	}
	path := strings.TrimPrefix(key, "detection.event.")
	ev := d.Event
	if ev == nil {
		return "", false
	}
	if ev.Unstructured != nil {
		if v, ok := ev.Unstructured[strings.ReplaceAll(path, ".", "_")]; ok {
			return fmt.Sprint(v), true
		}
	}
	if ev.Process != nil {
		if path == "pid" {
			return fmt.Sprintf("%d", ev.Process.PID), true
		}
		if path == "user" {
			return ev.Process.User, true
		}
		if path == "path" {
			return ev.Process.ProcessPath, true
		}
	}
	if ev.File != nil {
		if path == "path" {
			return ev.File.Path, true
		}
		if path == "pid" || path == "actor_pid" {
			return fmt.Sprintf("%d", ev.File.ActorPID), true
		}
	}
	if ev.Network != nil {
		if path == "dst_ip" || path == "dest_ip" {
			return ev.Network.DestIP, true
		}
		if path == "dst_port" || path == "dest_port" {
			return fmt.Sprintf("%d", ev.Network.DestPt), true
		}
		if path == "pid" {
			return fmt.Sprintf("%d", ev.Network.PID), true
		}
	}
	if ev.Injection != nil {
		if path == "source_pid" {
			return fmt.Sprintf("%d", ev.Injection.SourcePID), true
		}
	}
	return "", false
}
