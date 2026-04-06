//go:build darwin

package kernel

import "C"

import (
	"encoding/json"
	"time"
)

//export goESFEventCallback
func goESFEventCallback(eventType C.int, pid C.int, ppid C.int, uid C.int, gid C.int,
	comm *C.char, pathStr *C.char, args *C.char) {

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
	}

	envelope := map[string]interface{}{
		"type":      evtType,
		"timestamp": time.Now().UTC(),
		"agent_id":  d.agentID,
		"esf_type":  int(eventType),
		"pid":       int(pid),
		"ppid":      int(ppid),
		"uid":       int(uid),
		"gid":       int(gid),
		"comm":      safeGoString(comm),
		"path":      safeGoString(pathStr),
		"args":      safeGoString(args),
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

func safeGoString(s *C.char) string {
	if s == nil {
		return ""
	}
	return C.GoString(s)
}
