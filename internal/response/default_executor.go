package response

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/razatechofficial/edr/internal/detection"
	"github.com/razatechofficial/edr/internal/forensics"
	"github.com/razatechofficial/edr/internal/response/actions"
	"go.uber.org/zap"
)

// integrationTestNetworkIsolateHook, when set by this package's tests, bypasses real firewall
// commands so the pipeline can run in CI without mutating iptables/pf.
var integrationTestNetworkIsolateHook func(ctx context.Context, e *DefaultActionExecutor, params map[string]interface{}, d detection.Detection, log *zap.Logger) error

// DefaultActionExecutor dispatches YAML playbook op strings to handlers and [ActionEngine] ops.
type DefaultActionExecutor struct {
	Eng           *ActionEngine
	Logger        *zap.Logger
	ForensicsDir  string
	QuarantineDir string
	HostID        string
	AgentIP       string
	ForensicsDeep forensics.ForensicsDeepConfig
	OnForensic    func() // optional: called after successful collect_forensics
	// RegisterContainment, when set by [NewEngine], records isolations/quarantines/blocks in [RollbackManager].
	RegisterContainment func(Containment)
}

// Execute runs one playbook op (panic-free at boundary when called from [PlaybookEngine]).
func (e *DefaultActionExecutor) Execute(ctx context.Context, op string, params map[string]interface{}, d detection.Detection) (err error) {
	if e == nil {
		return nil
	}
	defer func() {
		if r := recover(); r != nil {
			if e.Logger != nil {
				e.Logger.Error("playbook op panic", zap.String("op", op), zap.Any("recover", r))
			}
			err = fmt.Errorf("playbook op %q panicked: %v", op, r)
		}
	}()
	log := e.Logger
	if log == nil {
		log = zap.NewNop()
	}
	correlationID := d.ID
	if correlationID == "" {
		correlationID = uuid.NewString()
	}
	log.Info("playbook action decision",
		zap.String("event_type", "response_decision"),
		zap.String("rule", d.RuleID),
		zap.String("target", stringParamAny(params, "target")),
		zap.String("action", op),
		zap.String("result", "started"),
		zap.String("reason", d.Description),
		zap.String("correlation_id", correlationID))
	switch op {
	case "kill_process":
		return e.runKill(ctx, params, d, log)
	case "collect_forensics":
		return e.runForensics(ctx, params, d, log)
	case "collect_artifacts":
		return e.runCollectArtifacts(ctx, params, d, log)
	case "alert":
		e.runAlert(ctx, params, d, log)
		return nil
	case "network_isolate":
		return e.runNetworkIsolate(ctx, params, d, log)
	case "network_block":
		return e.runNetworkBlock(ctx, params, d, log)
	case "file_quarantine":
		return e.runQuarantine(ctx, params, d, log)
	case "snapshot_create":
		return e.runSnapshot(ctx, params, log)
	case "user_disable":
		return e.runUserDisable(ctx, params, d, log)
	case "memory_dump", "process_dump":
		return e.runMemDump(ctx, params, d, log)
	default:
		log.Warn("unknown playbook op", zap.String("op", op))
		return nil
	}
}

func (e *DefaultActionExecutor) runKill(ctx context.Context, params map[string]interface{}, d detection.Detection, log *zap.Logger) error {
	if e.Eng == nil {
		return nil
	}
	tgt := stringParamAny(params, "target")
	pid, _ := strconv.Atoi(strings.TrimSpace(tgt))
	if pid <= 0 {
		if d.Event != nil && d.Event.Process != nil {
			pid = d.Event.Process.PID
		}
	}
	tree := boolParamAny(params, "include_children")
	steps := map[string]interface{}{"pid": pid, "mode": "kill", "tree": tree}
	if d.Event != nil && d.Event.Process != nil {
		steps["process_name"] = d.Event.Process.ProcessName
	}
	_, err := e.Eng.Execute(ctx, OpKillProcess, steps)
	return err
}

func (e *DefaultActionExecutor) runCollectArtifacts(ctx context.Context, params map[string]interface{}, d detection.Detection, log *zap.Logger) error {
	_ = params // reserved: memdump | filedump | regdump step filters
	meta := forensics.AlertTriggerMeta{
		AlertID:    d.ID,
		RuleID:     d.RuleID,
		Severity:   fmt.Sprint(d.Severity),
		EndpointID: e.HostID,
	}
	var deep *forensics.ForensicsDeepConfig
	if e.ForensicsDeep.AnyEnabled() {
		d := e.ForensicsDeep
		deep = &d
	}
	_, err := forensics.CollectArtifactsForAlert(ctx, log, meta, deep)
	return err
}

func (e *DefaultActionExecutor) runForensics(ctx context.Context, params map[string]interface{}, d detection.Detection, log *zap.Logger) error {
	var items []string
	if c, ok := params["collect"].([]interface{}); ok {
		for _, v := range c {
			if s, ok := v.(string); ok {
				switch s {
				case "file_artifacts":
					items = append(items, "open_files")
				case "process_memory", "lsass_handles":
					items = append(items, "network_state")
				default:
					items = append(items, s)
				}
			}
		}
	} else if c, ok := params["collect"].([]string); ok {
		items = append(items, c...)
	}
	coll := &actions.ForensicCollector{ForensicsDir: e.ForensicsDir, DetectionID: d.ID, Deep: e.ForensicsDeep}
	if coll.DetectionID == "" {
		coll.DetectionID = "unknown"
	}
	_, err := coll.Collect(ctx, items)
	if err != nil {
		return err
	}
	if e.OnForensic != nil {
		e.OnForensic()
	}
	_ = log
	return nil
}

func (e *DefaultActionExecutor) runAlert(_ context.Context, params map[string]interface{}, d detection.Detection, log *zap.Logger) {
	log.Info("playbook alert", zap.String("channel", stringParamAny(params, "channel")),
		zap.String("priority", stringParamAny(params, "priority")),
		zap.String("detection", d.ID))
}

func (e *DefaultActionExecutor) runNetworkIsolate(ctx context.Context, params map[string]interface{}, d detection.Detection, log *zap.Logger) error {
	if integrationTestNetworkIsolateHook != nil {
		return integrationTestNetworkIsolateHook(ctx, e, params, d, log)
	}
	allow := []string{}
	if a, ok := params["allow_list"].([]interface{}); ok {
		for _, v := range a {
			if s, ok := v.(string); ok {
				allow = append(allow, s)
			}
		}
	} else if a, ok := params["allow_list"].([]string); ok {
		allow = a
	}
	dur := intParamAny(params, "duration_minutes")
	act := &actions.NetworkIsolateAction{
		AllowList:       allow,
		DurationMinutes: dur,
		AgentIP:         e.AgentIP,
		BackupPath:      "",
	}
	rollback, err := act.Execute(ctx)
	if err != nil {
		return err
	}
	if rollback != nil {
		e.registerContainment(d, ActionNetworkIsolate, "network", dur, rollback)
	}
	_ = log
	return nil
}

func (e *DefaultActionExecutor) runNetworkBlock(ctx context.Context, params map[string]interface{}, d detection.Detection, log *zap.Logger) error {
	_ = d
	act := &actions.NetworkBlockAction{
		Direction:       stringParamAny(params, "direction"),
		DstIP:           stringParamAny(params, "dst_ip"),
		DstPort:         stringParamAny(params, "dst_port"),
		DurationMinutes: intParamAny(params, "duration_minutes"),
		RuleID:          uuid.NewString(),
	}
	rollback, err := act.Execute(ctx)
	if err != nil {
		return err
	}
	if rollback != nil {
		target := strings.TrimSpace(stringParamAny(params, "dst_ip") + ":" + stringParamAny(params, "dst_port"))
		if target == ":" {
			target = "network"
		}
		e.registerContainment(d, ActionNetworkBlock, target, act.DurationMinutes, rollback)
	}
	_ = log
	return nil
}

func (e *DefaultActionExecutor) runQuarantine(ctx context.Context, params map[string]interface{}, d detection.Detection, log *zap.Logger) error {
	path := stringParamAny(params, "path")
	qd := stringParamAny(params, "quarantine_dir")
	if qd == "" {
		qd = e.QuarantineDir
	}
	act := &actions.FileQuarantineAction{Path: path, QuarantineDir: qd, DetectionID: d.ID}
	rollback, err := act.Execute(ctx)
	if err != nil {
		return err
	}
	if rollback != nil {
		e.registerContainment(d, ActionFileQuarantine, path, 0, rollback)
	}
	_ = log
	return nil
}

func (e *DefaultActionExecutor) runSnapshot(ctx context.Context, params map[string]interface{}, log *zap.Logger) error {
	act := &actions.SnapshotAction{Reason: stringParamAny(params, "reason"), Logger: log}
	return act.Execute(ctx)
}

func (e *DefaultActionExecutor) runUserDisable(_ context.Context, params map[string]interface{}, d detection.Detection, log *zap.Logger) error {
	if b, ok := params["require_approval"].(bool); b && ok {
		if a, k := params["approved"].(bool); !k || !a {
			return fmt.Errorf("user_disable: approval required and not approved")
		}
	}
	log.Info("user_disable (stub: no system user API in agent)", zap.String("user", stringParamAny(params, "username")),
		zap.String("detection", d.ID))
	return nil
}

func (e *DefaultActionExecutor) runMemDump(ctx context.Context, params map[string]interface{}, d detection.Detection, log *zap.Logger) error {
	_ = params
	proc := ""
	var pid uint32
	if d.Event != nil && d.Event.Process != nil {
		proc = d.Event.Process.ProcessName
		pid = uint32(d.Event.Process.PID)
	}
	m := &actions.MemoryDump{PID: pid, ForensicsDir: e.ForensicsDir, ProcName: proc}
	if m.ForensicsDir == "" {
		m.ForensicsDir = e.ForensicsDir
	}
	err := m.Execute(ctx)
	_ = log
	return err
}

func stringParamAny(m map[string]interface{}, k string) string {
	if m == nil {
		return ""
	}
	v, ok := m[k]
	if !ok {
		return ""
	}
	switch t := v.(type) {
	case string:
		return t
	case float64:
		return strconv.FormatFloat(t, 'f', -1, 64)
	case int:
		return strconv.Itoa(t)
	default:
		return fmt.Sprint(t)
	}
}

func boolParamAny(m map[string]interface{}, k string) bool {
	if m == nil {
		return false
	}
	v, ok := m[k]
	if !ok {
		return false
	}
	b, _ := v.(bool)
	return b
}

func (e *DefaultActionExecutor) registerContainment(d detection.Detection, act Action, target string, durationMin int, rollback func(context.Context) error) {
	if e == nil || e.RegisterContainment == nil || rollback == nil {
		return
	}
	id := uuid.NewString()
	var exp time.Time
	if durationMin > 0 {
		exp = time.Now().Add(time.Duration(durationMin) * time.Minute)
	}
	e.RegisterContainment(Containment{
		ID:         id,
		HostID:     e.HostID,
		Action:     act,
		Target:     target,
		AppliedAt:  time.Now(),
		ExpiresAt:  exp,
		Detection:  d,
		Status:     ContainmentActive,
		RollbackFn: rollback,
	})
}

func intParamAny(m map[string]interface{}, k string) int {
	if m == nil {
		return 0
	}
	v, ok := m[k]
	if !ok {
		return 0
	}
	switch t := v.(type) {
	case int:
		return t
	case float64:
		return int(t)
	case int64:
		return int(t)
	case string:
		i, _ := strconv.Atoi(t)
		return i
	default:
		return 0
	}
}
