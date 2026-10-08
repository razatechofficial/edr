package response

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/razatechofficial/edr/internal/detection"
)

// ApprovalGateway decides whether an approval-gated playbook may run.
type ApprovalGateway interface {
	RequestApproval(ctx context.Context, d detection.Detection, pb PlaybookYAML) (bool, error)
}

// PlaybookYAML is metadata for approval (id + name + flags).
type PlaybookYAML struct {
	ID                 string
	Name               string
	ApprovalRequired   bool
	ApprovalTimeoutSec int
}

// AutoApprovalGateway always approves.
//
// It must be selected deliberately (response.approval.mode: auto). It is not a
// fallback: a playbook that declares approval_required asks a human to sanction
// an action that kills a process, isolates a host or moves a file away, and
// answering that automatically because nothing was configured defeats the
// declaration entirely.
type AutoApprovalGateway struct{}

// RequestApproval implements [ApprovalGateway].
func (g *AutoApprovalGateway) RequestApproval(_ context.Context, _ detection.Detection, _ PlaybookYAML) (bool, error) {
	return true, nil
}

// DenyApprovalGateway refuses every request, and is what an unconfigured
// deployment gets.
//
// Refusing leaves a destructive action untaken, which is recoverable. Approving
// by default takes it, which is not.
type DenyApprovalGateway struct {
	Logger *zap.Logger
}

// RequestApproval implements [ApprovalGateway].
func (g *DenyApprovalGateway) RequestApproval(_ context.Context, _ detection.Detection, pb PlaybookYAML) (bool, error) {
	if g != nil && g.Logger != nil {
		g.Logger.Warn("playbook requires approval but no approval mode is configured; refusing",
			zap.String("playbook", pb.ID),
			zap.String("name", pb.Name),
		)
	}
	return false, nil
}

var (
	webhookMu      sync.Mutex
	webhookSignals = map[string]chan bool{} // approvalID -> signal (true=approve, false=reject)
)

// SubmitApprovalResult is used by an HTTP callback handler to satisfy a pending [WebhookApprovalGateway] wait.
func SubmitApprovalResult(approvalID string, approved bool) {
	webhookMu.Lock()
	ch, ok := webhookSignals[approvalID]
	if ok {
		delete(webhookSignals, approvalID)
	}
	webhookMu.Unlock()
	if ok {
		select {
		case ch <- approved:
		default:
		}
	}
}

// WebhookApprovalGateway POSTs a Slack block message to WebhookURL and waits for [SubmitApprovalResult] or timeout.
type WebhookApprovalGateway struct {
	WebhookURL  string
	CallbackURL string
	TimeoutSec  int
	Client      *http.Client
	Logger      *zap.Logger
}

// RequestApproval implements [ApprovalGateway].
func (g *WebhookApprovalGateway) RequestApproval(ctx context.Context, d detection.Detection, pb PlaybookYAML) (bool, error) {
	if g.WebhookURL == "" {
		return false, fmt.Errorf("webhook: empty WebhookURL")
	}
	approvalID := uuid.NewString()
	ch := make(chan bool, 1)
	webhookMu.Lock()
	webhookSignals[approvalID] = ch
	webhookMu.Unlock()

	body := buildSlackMessage(approvalID, d, pb, g.CallbackURL)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, g.WebhookURL, bytes.NewReader(body))
	if err != nil {
		webhookMu.Lock()
		delete(webhookSignals, approvalID)
		webhookMu.Unlock()
		return false, err
	}
	req.Header.Set("Content-Type", "application/json")
	client := g.Client
	if client == nil {
		client = http.DefaultClient
	}
	if _, err := client.Do(req); err != nil {
		webhookMu.Lock()
		delete(webhookSignals, approvalID)
		webhookMu.Unlock()
		return false, err
	}

	tmo := g.TimeoutSec
	if tmo <= 0 {
		tmo = 300
	}
	timer := time.NewTimer(time.Duration(tmo) * time.Second)
	defer timer.Stop()
	select {
	case v := <-ch:
		return v, nil
	case <-ctx.Done():
		webhookMu.Lock()
		delete(webhookSignals, approvalID)
		webhookMu.Unlock()
		return false, ctx.Err()
	case <-timer.C:
		webhookMu.Lock()
		delete(webhookSignals, approvalID)
		webhookMu.Unlock()
		return false, nil
	}
}

func buildSlackMessage(approvalID string, d detection.Detection, pb PlaybookYAML, _ string) []byte {
	//nolint:lll
	return []byte(fmt.Sprintf(`{
  "text": "EDR Response Approval Required",
  "blocks": [
    {"type":"header","text":{"type":"plain_text",
     "text":"Response Approval Required"}},
    {"type":"section","fields":[
      {"type":"mrkdwn","text":"*Technique:*\n%s"},
      {"type":"mrkdwn","text":"*Severity:*\n%s"},
      {"type":"mrkdwn","text":"*Host:*\n%s"},
      {"type":"mrkdwn","text":"*Process:*\n%s"},
      {"type":"mrkdwn","text":"*Playbook:*\n%s"}
    ]},
    {"type":"actions","elements":[
      {"type":"button","text":{"type":"plain_text","text":"Approve"},
       "style":"primary","value":"%s","action_id":"approve_%s"},
      {"type":"button","text":{"type":"plain_text","text":"Reject"},
       "action_id":"reject_%s","value":"%s"}
    ]}
  ]
}`, d.TechniqueID, severityString(d.Severity), hostID(), processNameFromDetection(d),
		pb.Name, approvalID, approvalID, approvalID, approvalID))
}

func hostID() string {
	h, _ := os.Hostname()
	return h
}

func processNameFromDetection(d detection.Detection) string {
	if d.Event == nil {
		return ""
	}
	if d.Event.Process != nil {
		return d.Event.Process.ProcessName
	}
	return ""
}

// FileApprovalGateway watches ApprovalDir for {id}.approve or {id}.reject.
type FileApprovalGateway struct {
	ApprovalDir string
	Interval    time.Duration
}

// RequestApproval implements [ApprovalGateway].
func (g *FileApprovalGateway) RequestApproval(ctx context.Context, d detection.Detection, pb PlaybookYAML) (bool, error) {
	id := d.ID
	if id == "" {
		id = uuid.NewString()
	}
	approve := filepath.Join(g.ApprovalDir, id+".approve")
	reject := filepath.Join(g.ApprovalDir, id+".reject")
	interval := g.Interval
	if interval <= 0 {
		interval = 200 * time.Millisecond
	}
	tick := time.NewTicker(interval)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return false, ctx.Err()
		case <-tick.C:
			if _, err := os.Stat(approve); err == nil {
				_ = os.Remove(approve)
				return true, nil
			}
			if _, err := os.Stat(reject); err == nil {
				_ = os.Remove(reject)
				return false, nil
			}
		}
	}
}

func severityString(s detection.Severity) string {
	switch s {
	case detection.P0:
		return "P0"
	case detection.P1:
		return "P1"
	case detection.P2:
		return "P2"
	case detection.P3:
		return "P3"
	default:
		return "unknown"
	}
}

// ParseSeverityYAML parses P0|P1|P2|P3 from playbooks.
func ParseSeverityYAML(s string) (detection.Severity, error) {
	switch strings.TrimSpace(strings.ToUpper(s)) {
	case "P0":
		return detection.P0, nil
	case "P1":
		return detection.P1, nil
	case "P2":
		return detection.P2, nil
	case "P3":
		return detection.P3, nil
	default:
		return detection.P3, fmt.Errorf("unknown severity %q", s)
	}
}
