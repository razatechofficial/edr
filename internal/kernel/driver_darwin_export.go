//go:build darwin && cgo

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
	if d == nil {
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

	pathGo := safeGoString(pathStr)
	argTok := safeGoString(execArgs)
	envTok := safeGoString(execEnv)
	// C bridge uses ASCII RS (0x1e) between argv/env tokens; expose human spacing in "args".
	argsDisplay := strings.ReplaceAll(argTok, "\x1e", " ")
	envelope := map[string]interface{}{
		"type":      evtType,
		"timestamp": time.Now().UTC(),
		"agent_id":  d.agentID,
		"esf_type":  int(eventType),
		"seq":       d.esfSeq.Add(1),
		"pid":       int(pid),
		"ppid":      int(ppid),
		"uid":       int(uid),
		"gid":       int(gid),
		"comm":      safeGoString(comm),
		"path":      pathGo,
		"args":      argsDisplay,
		"exec_env":  envTok,
	}
	classifyAppleScriptEnvelope(envelope, pathGo, argsDisplay)
	if esfIsExecEvent(int(eventType)) {
		if pathGo != "" {
			tid, cdh, flg := esfExecSigningInfo(pathGo)
			if tid != "" {
				envelope["signing_team_id"] = tid
			}
			if cdh != "" {
				envelope["image_cdhash"] = cdh
			}
			envelope["signing_flags"] = flg
			envelope["signing_status"] = esfSigningStatus(flg)
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
func goESFAuthCallback(eventType C.int, pid C.int, comm *C.char, pathStr *C.char) C.int {
	d := globalESF.Load()
	if d == nil {
		return 0
	}

	// Copy C strings before any async work to avoid use-after-free.
	pathKey := safeGoString(pathStr)
	commStr := safeGoString(comm)

	if decision, ok := d.cache.get(pathKey); ok {
		if decision == AuthDeny {
			return 1
		}
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
			return 1
		}
		return 0
	case <-time.After(d.authTimeout):
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

func safeGoString(s *C.char) string {
	if s == nil {
		return ""
	}
	return C.GoString(s)
}
