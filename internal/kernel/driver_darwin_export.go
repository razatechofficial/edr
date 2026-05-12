//go:build darwin && cgo && !nosec

package kernel

import "C"

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"time"
)

//export goESFEventCallback
func goESFEventCallback(eventType C.int, pid C.int, ppid C.int, uid C.int, gid C.int,
	comm *C.char, pathStr *C.char, execArgs *C.char, execEnv *C.char) {

	d := globalESF.Load()
	if d == nil || d.notifyCh == nil {
		return
	}
	d.received.Add(1)

	evtType := mapESFEventType(int(eventType))

	d.mu.RLock()
	p := d.policy
	d.mu.RUnlock()

	switch evtType {
	case "process":
		if !p.ProcessEvents {
			return
		}
	case "file":
		if !p.FileEvents {
			return
		}
	case "memory":
		if !p.MemoryEvents {
			return
		}
	case "module":
		if !p.ModuleEvents {
			return
		}
	case "mount":
		if !p.MountEvents {
			return
		}
	case "signal":
		if !p.SignalEvents {
			return
		}
	case "ptrace":
		if !p.PtraceEvents {
			return
		}
	}

	payload := ESFNotifyPayload{
		EventType: int(eventType),
		PID:       int(pid),
		PPID:      int(ppid),
		UID:       int(uid),
		GID:       int(gid),
		Comm:      safeGoString(comm),
		Path:      safeGoString(pathStr),
		Args:      safeGoString(execArgs),
		Env:       safeGoString(execEnv),
	}
	select {
	case d.notifyCh <- payload:
	default:
		d.notifyDropped.Add(1)
		d.dropped.Add(1)
	}
}

func processESFNotifyPayload(d *ESFDriver, p *ESFNotifyPayload) {
	if d == nil || p == nil {
		return
	}
	evtType := mapESFEventType(p.EventType)
	pathGo := p.Path
	argTok := p.Args
	envTok := p.Env
	argsDisplay := strings.ReplaceAll(argTok, "\x1e", " ")
	// P2-9: reuse envelope maps across events to amortize allocation cost.
	envelope := getEnvelope()
	defer putEnvelope(envelope)
	envelope["type"] = evtType
	envelope["timestamp"] = time.Now().UTC()
	envelope["agent_id"] = d.agentID
	envelope["esf_type"] = p.EventType
	envelope["esf_op"] = esfOperationName(p.EventType)
	envelope["seq"] = d.esfSeq.Add(1)
	envelope["pid"] = p.PID
	envelope["ppid"] = p.PPID
	envelope["uid"] = p.UID
	envelope["gid"] = p.GID
	envelope["comm"] = p.Comm
	envelope["path"] = pathGo
	envelope["args"] = argsDisplay
	envelope["exec_env"] = envTok
	classifyAppleScriptEnvelope(envelope, pathGo, argsDisplay)
	if esfIsExecEvent(p.EventType) {
		if pathGo != "" {
			tid, cdh, flg, valid := esfExecSigningInfoFull(pathGo)
			if tid != "" {
				envelope["signing_team_id"] = tid
			}
			if cdh != "" {
				envelope["image_cdhash"] = cdh
			}
			envelope["signing_flags"] = flg
			// P1-11: surface signature validity. A non-empty teamID with
			// valid_signature=false means the binary advertises signing
			// metadata that does not verify — typical for tampered
			// binaries and a high-signal detection input.
			envelope["valid_signature"] = valid
			envelope["signing_status"] = esfSigningStatusValidated(flg, tid, valid)
		}
	}

	data, err := json.Marshal(envelope)
	if err != nil {
		d.errors.Add(1)
		d.dropped.Add(1)
		return
	}
	if err := d.buf.Write(data); err != nil {
		d.dropped.Add(1)
		return
	}
	d.processed.Add(1)
}

func classifyAppleScriptEnvelope(envelope map[string]interface{}, pathGo, args string) {
	base := strings.ToLower(filepath.Base(pathGo))
	if !strings.Contains(base, "osascript") && !strings.Contains(base, "osacompile") && !strings.Contains(strings.ToLower(args), "-e") {
		return
	}
	tags := []string{"applescript"}
	if strings.Contains(strings.ToLower(args), "-e") {
		tags = append(tags, "inline_script")
	}
	envelope["tags"] = strings.Join(tags, ",")
	if p, ok := envelope["path"].(string); ok {
		lp := strings.ToLower(p)
		if strings.Contains(lp, "chrome") || strings.Contains(lp, "safari") || strings.Contains(lp, "firefox") ||
			strings.Contains(lp, "outlook") || strings.Contains(lp, "mail") || strings.Contains(lp, "word") || strings.Contains(lp, "excel") {
			envelope["severity"] = "P1"
		}
	}
}

//export goESFAuthCallback
func goESFAuthCallback(eventType C.int, pid C.int, comm *C.char, pathStr *C.char, budgetMs C.int) C.int {
	d := globalESF.Load()
	if d == nil {
		return 0
	}

	// Copy C strings before any async work to avoid use-after-free.
	pathKey := safeGoString(pathStr)
	commStr := safeGoString(comm)

	budget := int(budgetMs)
	if budget >= 0 {
		d.observeAuthBudgetMs(budget)
	}
	d.mu.RLock()
	denyTh := d.policy.ESFAuthDenyBudgetMs
	d.mu.RUnlock()
	if denyTh > 0 && budget >= 0 && budget < denyTh {
		d.authBudgetDenyLow.Add(1)
		d.authDenials.Add(1)
		return 1
	}
	wait := d.authTimeout
	if budget >= 0 {
		if budget == 0 {
			wait = 5 * time.Millisecond
		} else {
			bd := time.Duration(budget) * time.Millisecond
			if bd < wait {
				wait = bd
			}
		}
	}
	if wait < time.Millisecond {
		wait = time.Millisecond
	}

	if decision, ok := d.cache.get(pathKey); ok {
		d.authCacheHits.Add(1)
		if decision == AuthDeny {
			d.authDenials.Add(1)
			return 1
		}
		return 0
	}

	// P1-9: trusted-team-id fast path. Apple, Microsoft and the EDR's
	// own developer team identifiers can be allowlisted via policy so
	// signed binaries skip the goroutine-bound handler dispatch and
	// respond immediately. Only signed binaries with a matching team id
	// qualify — unsigned and adhoc-signed binaries always fall through
	// to full analysis.
	if pathKey != "" && d.isTrustedTeamPath(pathKey) {
		d.authCacheHits.Add(1)
		// Cache the allow decision so subsequent invocations short-
		// circuit at the per-path cache (cheaper than re-evaluating
		// signing on every AUTH event).
		d.cache.set(pathKey, AuthAllow)
		return 0
	}

	d.authMu.RLock()
	handler := d.authHandler
	d.authMu.RUnlock()

	if handler == nil {
		return 0
	}

	type authResult struct {
		decision AuthDecision
	}
	ch := make(chan authResult, 1)
	go func() {
		evt := map[string]interface{}{
			"esf_type": int(eventType),
			"pid":      int(pid),
			"comm":     commStr,
			"path":     pathKey,
		}
		ch <- authResult{handler(evt)}
	}()

	select {
	case r := <-ch:
		d.cache.set(pathKey, r.decision)
		if r.decision == AuthDeny {
			d.authDenials.Add(1)
			return 1
		}
		return 0
	case <-time.After(wait):
		d.authTimeouts.Add(1)
		if budget >= 0 && time.Duration(budget)*time.Millisecond <= wait+2*time.Millisecond {
			d.authDeadlineViolations.Add(1)
		}
		d.cache.set(pathKey, AuthAllow)
		return 0
	}
}

// esfSigningStatus maps SecCode signature flags to a coarse signed/adhoc/unsigned label.
func esfSigningStatus(flags uint32) string {
	const secCodeSignatureAdhoc = 0x00000002
	if flags == 0 {
		return "unsigned"
	}
	if flags&secCodeSignatureAdhoc != 0 {
		return "adhoc"
	}
	return "signed"
}

// esfSigningStatusValidated extends esfSigningStatus with a
// SecStaticCodeCheckValidity result (P1-11). A binary that advertises a
// non-empty teamID but fails the integrity check is labeled
// "invalid_signature" to distinguish it from genuine "unsigned" so
// detection rules can fire on tampered binaries specifically.
func esfSigningStatusValidated(flags uint32, teamID string, valid bool) string {
	base := esfSigningStatus(flags)
	if base == "signed" && !valid {
		return "invalid_signature"
	}
	if teamID != "" && !valid {
		return "invalid_signature"
	}
	return base
}

func safeGoString(s *C.char) string {
	if s == nil {
		return ""
	}
	return C.GoString(s)
}
