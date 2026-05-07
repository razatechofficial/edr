package collector

import (
	"encoding/json"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/razatechofficial/edr/internal/schema"
)

// MapKernelJSONToTelemetry maps kernel driver JSON (Linux eBPF JSON path, ESF,
// ETW envelopes) into schema telemetry. Returns nil if the payload is not recognized.
// users resolves numeric UIDs in JSON to usernames for ProcessEvent.User when non-nil.
func MapKernelJSONToTelemetry(data []byte, endpointID, hostname, goos string, users *UsernameCache) *Telemetry {
	var raw map[string]interface{}
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil
	}

	evType, _ := raw["type"].(string)
	evType = strings.TrimSpace(strings.ToLower(evType))
	if evType == "" {
		return nil
	}

	ts := parseKernelJSONTime(raw)
	base := schema.BaseEvent{
		SchemaVersion: schema.SchemaVersionV1,
		EndpointID:    endpointID,
		Timestamp:     ts,
		Hostname:      hostname,
		OS:            goos,
	}

	switch evType {
	case "process":
		if op := strings.ToLower(jsonString(raw, "operation")); op == "cgroup_attach" || op == "cgroup_mkdir" {
			base.EventType = schema.EventProcess
			ce := &schema.ContainerEvent{
				BaseEvent:   base,
				Operation:   op,
				PID:         jsonInt(raw, "pid"),
				ProcessName: firstNonEmpty(jsonString(raw, "process_name"), jsonString(raw, "comm")),
				Path:        jsonString(raw, "path"),
				Mode:        jsonUint32(raw, "mode"),
			}
			return &Telemetry{Container: ce}
		}
		if op := strings.ToLower(jsonString(raw, "operation")); op == "seccomp_filter_install" {
			base.EventType = schema.EventProcess
			sp := &schema.SecurityPolicyEvent{
				BaseEvent: base,
				Operation: op,
				PID:       jsonInt(raw, "pid"),
				Flags:     jsonUint64(raw, "flags", "arg1"),
			}
			return &Telemetry{SecPolicy: sp}
		}
		if op := strings.ToLower(jsonString(raw, "operation")); strings.HasPrefix(op, "sched_") {
			base.EventType = schema.EventProcess
			pe := &schema.ProcessEvent{BaseEvent: base}
			pe.PID = jsonInt(raw, "pid")
			pe.ProcessName = firstNonEmpty(jsonString(raw, "process_name"), jsonString(raw, "comm"))
			pe.CommandLine = strings.TrimSpace(strings.Join([]string{
				op,
				"prev_pid=" + strconv.FormatInt(int64(jsonInt(raw, "sched_prev_pid")), 10),
				"next_pid=" + strconv.FormatInt(int64(jsonInt(raw, "sched_next_pid")), 10),
				"cpu=" + strconv.FormatInt(int64(jsonInt(raw, "sched_cpu")), 10),
				"target_cpu=" + strconv.FormatInt(int64(jsonInt(raw, "sched_target_cpu")), 10),
				"runtime_ns=" + strconv.FormatUint(jsonUint64(raw, "sched_runtime_ns"), 10),
			}, " "))
			pe.Tags = []string{"kernel_sched", op}
			applyProcessUserFromJSON(pe, raw, users)
			return &Telemetry{Process: pe}
		}
		if op := strings.ToLower(jsonString(raw, "operation")); strings.Contains(op, "ebpf_program_missing") {
			base.EventType = schema.EventProcess
			te := &schema.TamperEvent{
				BaseEvent: base,
				Component: "ebpf_program",
				ProgramID: jsonUint32(raw, "program_id"),
				Message:   op,
			}
			return &Telemetry{Tamper: te}
		}
		base.EventType = schema.EventProcess
		pe := &schema.ProcessEvent{BaseEvent: base}
		childPID := jsonInt(raw, "child_pid")
		exitPID := jsonInt(raw, "exit_pid")
		loggerPID := jsonInt(raw, "pid")
		switch {
		case exitPID != 0:
			pe.PID = exitPID
			pe.PPID = jsonInt(raw, "ppid", "parent_pid")
		case childPID != 0:
			// ETW process start (and similar): subject is the child process.
			pe.PID = childPID
			pe.PPID = jsonInt(raw, "parent_pid", "ppid")
			if pe.PPID == 0 && loggerPID != 0 {
				pe.PPID = loggerPID
			}
		default:
			pe.PID = loggerPID
			pe.PPID = jsonInt(raw, "ppid", "parent_pid")
		}
		pe.ChildPID = childPID
		pe.ProcessName = firstNonEmpty(
			jsonString(raw, "process_name"),
			jsonString(raw, "comm"),
			filepath.Base(jsonString(raw, "path")),
		)
		pe.ProcessPath = firstNonEmpty(
			jsonString(raw, "process_path"),
			jsonString(raw, "path"),
			jsonString(raw, "image_name"),
		)
		pe.CommandLine = firstNonEmpty(
			jsonString(raw, "command_line"),
			jsonString(raw, "args"),
		)
		pe.SigningTeamID = jsonString(raw, "signing_team_id")
		pe.ImageCDHash = jsonString(raw, "image_cdhash")
		pe.SigningFlags = jsonUint32(raw, "signing_flags")
		pe.ImageSHA256 = jsonString(raw, "image_sha256")
		pe.SigningStatus = jsonString(raw, "signing_status")
		pe.TLSClientJA3 = firstNonEmpty(jsonString(raw, "tls_client_ja3"), jsonString(raw, "ja3"))
		pe.CloneFlags = jsonUint64(raw, "clone_flags")
		pe.UnshareFlags = jsonUint64(raw, "unshare_flags")
		pe.MadviseAdvice = int32(jsonInt(raw, "madvise_advice"))
		pe.ExecEnv = jsonString(raw, "exec_env")
		if tg := jsonString(raw, "tags"); tg != "" {
			pe.Tags = strings.Split(tg, ",")
		}
		pe.Severity = jsonString(raw, "severity")
		applyProcessUserFromJSON(pe, raw, users)
		return &Telemetry{Process: pe}

	case "injection":
		base.EventType = schema.EventInjection
		ie := &schema.ProcessInjectionEvent{BaseEvent: base}
		ie.SourcePID = jsonInt(raw, "source_pid")
		ie.TargetPID = jsonInt(raw, "target_pid")
		ie.TargetImage = jsonString(raw, "target_image")
		ie.Technique = jsonString(raw, "technique")
		return &Telemetry{Injection: ie}

	case "credential_access":
		base.EventType = schema.EventProcess
		ce := &schema.CredentialAccessEvent{BaseEvent: base}
		ce.Technique = jsonString(raw, "technique")
		ce.SourcePID = uint32(jsonInt(raw, "source_pid"))
		ce.SourceProcess = jsonString(raw, "source_process")
		ce.TargetPath = firstNonEmpty(jsonString(raw, "target_path"), jsonString(raw, "target_process"))
		ce.AccessMask = jsonUint32(raw, "access_mask")
		ce.Severity = jsonString(raw, "severity")
		return &Telemetry{Credential: ce}

	case "memory":
		base.EventType = schema.EventProcess
		me := &schema.MemoryEvent{BaseEvent: base}
		me.Operation = jsonString(raw, "operation")
		me.TargetPID = uint32(jsonInt(raw, "target_pid"))
		me.TargetProcess = jsonString(raw, "target_process")
		me.Address = jsonUint64(raw, "address")
		me.Size = jsonUint64(raw, "size", "region_size")
		me.Protect = jsonUint32(raw, "protect")
		return &Telemetry{Memory: me}

	case "persistence":
		base.EventType = schema.EventProcess
		pe := &schema.PersistenceEvent{BaseEvent: base}
		pe.Technique = jsonString(raw, "technique")
		pe.ExecutablePath = firstNonEmpty(jsonString(raw, "executable_path"), jsonString(raw, "path"))
		pe.ItemType = jsonString(raw, "item_type")
		pe.IsLegacy = jsonInt(raw, "legacy") == 1
		pe.IsManaged = jsonInt(raw, "managed") == 1
		pe.UID = uint32(jsonInt(raw, "uid"))
		pe.PID = uint32(jsonInt(raw, "pid"))
		pe.ProcessPath = jsonString(raw, "process_path")
		return &Telemetry{Persistence: pe}

	case "privacy":
		base.EventType = schema.EventProcess
		pe := &schema.PrivacyEvent{BaseEvent: base}
		pe.Operation = jsonString(raw, "operation")
		pe.Service = jsonString(raw, "service")
		pe.AuthValue = jsonInt(raw, "auth_value")
		pe.AuthReason = jsonString(raw, "auth_reason")
		pe.AccessingPID = uint32(jsonInt(raw, "accessing_pid", "pid"))
		pe.AccessingProcess = firstNonEmpty(jsonString(raw, "accessing_process"), jsonString(raw, "process_name"))
		return &Telemetry{Privacy: pe}

	case "gatekeeper_bypass":
		base.EventType = schema.EventProcess
		ge := &schema.GatekeeperBypassEvent{BaseEvent: base}
		ge.FilePath = jsonString(raw, "file_path")
		ge.PID = uint32(jsonInt(raw, "pid"))
		ge.ProcessPath = jsonString(raw, "process_path")
		ge.SigningStatus = jsonString(raw, "signing_status")
		return &Telemetry{Gatekeeper: ge}

	case "dropped_events":
		base.EventType = schema.EventProcess
		de := &schema.DroppedEventsEvent{BaseEvent: base}
		de.EventClass = jsonString(raw, "event_class")
		de.GapSize = jsonUint64(raw, "gap_size")
		de.LastSeq = jsonUint64(raw, "last_seq")
		de.CurrentSeq = jsonUint64(raw, "current_seq")
		return &Telemetry{Dropped: de}

	case "ti_status":
		base.EventType = schema.EventProcess
		ts := &schema.TIStatusEvent{BaseEvent: base}
		ts.Status = jsonString(raw, "status")
		ts.Reason = jsonString(raw, "reason")
		return &Telemetry{TIStatus: ts}

	case "feature_status":
		base.EventType = schema.EventProcess
		fs := &schema.FeatureStatusEvent{BaseEvent: base}
		features := map[string]bool{}
		for _, k := range []string{"has_bpf_lsm", "has_cgroup_bpf", "has_btf"} {
			features[k] = jsonInt(raw, k) == 1
		}
		fs.Features = features
		return &Telemetry{FeatureStatus: fs}

	case "fork":
		base.EventType = schema.EventFork
		fk := &schema.ForkEvent{BaseEvent: base}
		fk.ParentPID = jsonInt(raw, "parent_pid")
		if fk.ParentPID == 0 {
			fk.ParentPID = jsonInt(raw, "ppid")
		}
		if fk.ParentPID == 0 {
			fk.ParentPID = jsonInt(raw, "pid")
		}
		fk.ChildPID = jsonInt(raw, "child_pid")
		fk.CloneFlags = jsonUint64(raw, "clone_flags")
		if fk.CloneFlags&0x100 != 0 { // CLONE_VM
			fk.IsThread = true
		}
		const cloneNsMask = uint64(0x20000 | 0x2000000 | 0x4000000 | 0x8000000 | 0x10000000 | 0x20000000 | 0x40000000)
		fk.IsContainer = fk.CloneFlags&cloneNsMask != 0
		return &Telemetry{Fork: fk}

	case "file":
		base.EventType = schema.EventFile
		fe := &schema.FileEvent{BaseEvent: base}
		fe.Path = firstNonEmpty(jsonString(raw, "path"), jsonString(raw, "file_name"))
		fe.Operation = jsonString(raw, "operation")
		if fe.Operation == "" {
			fe.Operation = "event"
		}
		fe.ActorPID = jsonInt(raw, "pid")
		fe.ActorPPID = jsonInt(raw, "ppid", "actor_ppid")
		fe.AuditUID = jsonString(raw, "audit_uid")
		fe.EffectiveUID = firstNonEmpty(jsonString(raw, "effective_uid"), jsonString(raw, "euid"))
		fe.ActorComm = firstNonEmpty(jsonString(raw, "actor_comm"), jsonString(raw, "comm"))
		fe.ActorExe = firstNonEmpty(jsonString(raw, "actor_exe"), jsonString(raw, "exe"), jsonString(raw, "process_path"))
		fe.Syscall = jsonString(raw, "syscall")
		fe.SubjectUID = firstNonEmpty(jsonString(raw, "subject_uid"), jsonString(raw, "audit_uid"), fe.AuditUID)
		fe.Hash = jsonString(raw, "hash")
		fe.WriteFD = jsonInt(raw, "write_fd")
		fe.BytesWritten = jsonUint64(raw, "bytes_written")
		fe.OpenFlags = jsonUint32(raw, "open_flags")
		fe.ChmodMode = jsonUint32(raw, "chmod_mode")
		fe.FchmodatFlags = jsonUint32(raw, "fchmodat_flags")
		return &Telemetry{File: fe}

	case "network":
		base.EventType = schema.EventNetwork
		ne := &schema.NetworkEvent{BaseEvent: base, PID: jsonInt(raw, "pid")}
		ne.Protocol = jsonString(raw, "protocol")
		ne.Transport = firstNonEmpty(jsonString(raw, "transport"), "")
		ne.CommunityID = firstNonEmpty(jsonString(raw, "community_id"), "")
		ne.SourceIP = firstNonEmpty(jsonString(raw, "source_ip"), jsonString(raw, "src"))
		ne.DestIP = firstNonEmpty(jsonString(raw, "dest_ip"), jsonString(raw, "dst"), jsonString(raw, "dst_addr"))
		ne.SourcePt = jsonInt(raw, "source_port", "src_port")
		ne.DestPt = jsonInt(raw, "dest_port", "dst_port")
		ne.JA3 = firstNonEmpty(jsonString(raw, "tls_client_ja3"), jsonString(raw, "ja3"))
		return &Telemetry{Network: ne}

	case "dns":
		base.EventType = schema.EventNetwork
		ne := &schema.NetworkEvent{BaseEvent: base, PID: jsonInt(raw, "pid"), Protocol: "dns"}
		ne.Domain = firstNonEmpty(jsonString(raw, "query"), jsonString(raw, "domain"), jsonString(raw, "query_name"))
		return &Telemetry{Network: ne}

	case "registry":
		base.EventType = schema.EventRegistry
		re := &schema.RegistryEvent{BaseEvent: base}
		re.KeyPath = firstNonEmpty(jsonString(raw, "key_path"), jsonString(raw, "path"))
		re.ValueName = jsonString(raw, "value_name")
		re.Operation = firstNonEmpty(jsonString(raw, "operation"), "event")
		re.OldData = jsonString(raw, "old_data")
		re.NewData = jsonString(raw, "new_data")
		re.ActorPID = jsonInt(raw, "pid")
		return &Telemetry{Registry: re}

	case "module", "mount", "signal", "ptrace":
		base.EventType = schema.EventProcess
		pe := &schema.ProcessEvent{BaseEvent: base}
		pe.PID = jsonInt(raw, "pid", "image_load_pid", "image_unload_pid")
		// Refine ProcessName for image-load events so detection rules can
		// scope to dylib mmap or kernel extension load specifically.
		// macOS ESF stamps esf_op; Windows ETW stamps op (image_load,
		// image_unload). Fall back to evType if neither is provided.
		op := firstNonEmpty(jsonString(raw, "esf_op"), jsonString(raw, "op"))
		switch {
		case evType == "module" && op == "image_load":
			pe.ProcessName = "image_load"
		case evType == "module" && op == "image_unload":
			pe.ProcessName = "image_unload"
		case evType == "module" && op == "kextload":
			pe.ProcessName = "kextload"
		case op != "" && op != "unknown":
			pe.ProcessName = op
		default:
			pe.ProcessName = evType
		}
		pe.ProcessPath = firstNonEmpty(
			jsonString(raw, "path"),
			jsonString(raw, "module_path"),
			jsonString(raw, "image_name"),
		)
		pe.CommandLine = jsonString(raw, "message")
		applyProcessUserFromJSON(pe, raw, users)
		return &Telemetry{Process: pe}

	case "namespace":
		base.EventType = schema.EventProcess
		pe := &schema.ProcessEvent{BaseEvent: base}
		pe.PID = jsonInt(raw, "pid")
		pe.ProcessName = "namespace"
		pe.ProcessPath = jsonString(raw, "process_name")
		pe.UnshareFlags = jsonUint64(raw, "unshare_flags")
		pe.CommandLine = jsonString(raw, "command_line")
		applyProcessUserFromJSON(pe, raw, users)
		return &Telemetry{Process: pe}

	case "madvise":
		base.EventType = schema.EventProcess
		pe := &schema.ProcessEvent{BaseEvent: base}
		pe.PID = jsonInt(raw, "pid")
		pe.ProcessName = "madvise"
		pe.ProcessPath = jsonString(raw, "process_name")
		pe.MadviseAdvice = int32(jsonInt(raw, "madvise_advice"))
		pe.CommandLine = jsonString(raw, "command_line")
		applyProcessUserFromJSON(pe, raw, users)
		return &Telemetry{Process: pe}

	case "wmi", "powershell", "pipe", "bits", "task":
		base.EventType = schema.EventProcess
		pe := &schema.ProcessEvent{BaseEvent: base}
		pe.PID = jsonInt(raw, "pid")
		pe.ProcessName = evType
		pe.ProcessPath = firstNonEmpty(
			jsonString(raw, "path"),
			jsonString(raw, "task_name"),
			jsonString(raw, "url"),
		)
		pe.CommandLine = firstNonEmpty(
			jsonString(raw, "script_block"),
			jsonString(raw, "task_action"),
			jsonString(raw, "message"),
			jsonString(raw, "query"),
			jsonString(raw, "etw_user_data_prefix_hex"),
		)
		applyProcessUserFromJSON(pe, raw, users)
		return &Telemetry{Process: pe}

	default:
		return nil
	}
}

func applyProcessUserFromJSON(pe *schema.ProcessEvent, raw map[string]interface{}, users *UsernameCache) {
	if pe == nil || users == nil {
		return
	}
	uid := jsonUIDString(raw, "uid", "user_id", "ruid", "euid")
	if uid == "" {
		return
	}
	pe.User = users.Lookup(uid)
}

func jsonUIDString(m map[string]interface{}, keys ...string) string {
	for _, key := range keys {
		v, ok := m[key]
		if !ok || v == nil {
			continue
		}
		switch x := v.(type) {
		case string:
			s := strings.TrimSpace(x)
			if s != "" {
				return s
			}
		case float64:
			return strconv.FormatInt(int64(x), 10)
		case int:
			return strconv.Itoa(x)
		case int64:
			return strconv.FormatInt(x, 10)
		case uint64:
			return strconv.FormatUint(x, 10)
		case json.Number:
			i, err := x.Int64()
			if err == nil {
				return strconv.FormatInt(i, 10)
			}
		}
	}
	return ""
}

func parseKernelJSONTime(raw map[string]interface{}) time.Time {
	if v, ok := raw["timestamp"].(string); ok {
		if t, err := time.Parse(time.RFC3339Nano, v); err == nil {
			return t.UTC()
		}
		if t, err := time.Parse(time.RFC3339, v); err == nil {
			return t.UTC()
		}
	}
	return time.Now().UTC()
}

func jsonString(m map[string]interface{}, key string) string {
	v, ok := m[key]
	if !ok || v == nil {
		return ""
	}
	switch s := v.(type) {
	case string:
		return s
	default:
		return ""
	}
}

func jsonUint32(m map[string]interface{}, key string) uint32 {
	v, ok := m[key]
	if !ok || v == nil {
		return 0
	}
	switch x := v.(type) {
	case float64:
		return uint32(x)
	case int:
		return uint32(x)
	case int64:
		return uint32(x)
	case uint64:
		return uint32(x)
	case uint32:
		return x
	case json.Number:
		i, _ := x.Int64()
		return uint32(i)
	}
	return 0
}

func jsonUint64(m map[string]interface{}, keys ...string) uint64 {
	for _, key := range keys {
		v, ok := m[key]
		if !ok || v == nil {
			continue
		}
		switch x := v.(type) {
		case float64:
			return uint64(x)
		case int:
			return uint64(x)
		case int64:
			return uint64(x)
		case uint64:
			return x
		case uint32:
			return uint64(x)
		case json.Number:
			i, _ := x.Int64()
			return uint64(i)
		}
	}
	return 0
}

func jsonInt(m map[string]interface{}, keys ...string) int {
	for _, key := range keys {
		v, ok := m[key]
		if !ok || v == nil {
			continue
		}
		switch x := v.(type) {
		case float64:
			return int(x)
		case int:
			return x
		case int64:
			return int(x)
		case uint64:
			return int(x)
		case uint32:
			return int(x)
		case json.Number:
			i, _ := x.Int64()
			return int(i)
		}
	}
	return 0
}

func firstNonEmpty(vals ...string) string {
	for _, s := range vals {
		if strings.TrimSpace(s) != "" {
			return s
		}
	}
	return ""
}
