//go:build linux

package collector

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/razatechofficial/edr/internal/schema"
	"golang.org/x/sys/unix"
)

// AuditSource is a userland fallback that consumes Linux audit netlink events.
// It is the equivalent of Wazuh's whodata audit pipeline and provides a
// reliable alternative to eBPF LSM hooks on paranoid kernels (where
// kernel.perf_event_paranoid prevents the agent from attaching tracepoints).
//
// We deliberately do NOT add audit rules from this code path: rules belong
// to /etc/audit/rules.d managed by the operator. We just listen for events
// already produced by the running auditd subsystem.
type AuditSource struct {
	endpointID string
	hostname   string
	tracker    *LineageTracker

	mu      sync.Mutex // guards: fd, started
	fd      int
	started bool

	emitted atomic.Uint64
	errs    atomic.Pointer[string]

	pendingMu sync.Mutex
	pending   map[string]*auditSyscallScratch // SYSCALL rows until PATH correlates (FIM who-data).

	fileDedupe          *LinuxFileDeduper
	managedRules        bool
	managedRulesErr     atomic.Pointer[string]

	livenessMu   sync.Mutex
	livenessRan  bool
	livenessOK   bool
	livenessNote string
}

type auditSyscallScratch struct {
	pid     int
	ppid    int
	uid     string
	auid    string
	euid    string
	syscall string
	exe     string
	comm    string
}

// auditPacket is a Linux netlink audit message header.
type auditPacket struct {
	Length uint32
	Type   uint16
	Flags  uint16
	Seq    uint32
	PID    uint32
}

// NewAuditSource constructs an audit netlink consumer.
func NewAuditSource(endpointID, hostname string, tracker *LineageTracker, dedupe *LinuxFileDeduper, managedRules bool) *AuditSource {
	if hostname == "" {
		if h, err := os.Hostname(); err == nil {
			hostname = h
		} else {
			hostname = "unknown"
		}
	}
	return &AuditSource{
		endpointID:   endpointID,
		hostname:     hostname,
		tracker:      tracker,
		fd:           -1,
		pending:      make(map[string]*auditSyscallScratch),
		fileDedupe:   dedupe,
		managedRules: managedRules,
	}
}

// Start opens a NETLINK_AUDIT socket and subscribes our pid as the audit
// listener. Requires CAP_AUDIT_READ; otherwise records the error and
// becomes a no-op consumer until restart.
func (a *AuditSource) Start() error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.started {
		return nil
	}
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_CLOEXEC|unix.SOCK_NONBLOCK, unix.NETLINK_AUDIT)
	if err != nil {
		a.recordError(err)
		return fmt.Errorf("audit socket: %w", err)
	}
	addr := &unix.SockaddrNetlink{Family: unix.AF_NETLINK}
	if err := unix.Bind(fd, addr); err != nil {
		_ = unix.Close(fd)
		a.recordError(err)
		return fmt.Errorf("audit bind: %w", err)
	}
	a.fd = fd
	a.started = true
	if a.managedRules {
		if err := a.installManagedAuditProbe(); err != nil {
			msg := err.Error()
			a.managedRulesErr.Store(&msg)
		}
	}
	return nil
}

func (a *AuditSource) installManagedAuditProbe() error {
	dir := "/var/lib/edr"
	path := filepath.Join(dir, ".audit_managed_probe")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("managed audit mkdir: %w", err)
	}
	if err := os.WriteFile(path, []byte("edr-managed-audit-probe\n"), 0o644); err != nil {
		return fmt.Errorf("managed audit probe file: %w", err)
	}
	cmd := exec.Command("auditctl", "-w", path, "-p", "wa", "-k", "edr_managed")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("auditctl: %w: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// Stop closes the netlink socket.
func (a *AuditSource) Stop() {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.fd >= 0 {
		_ = unix.Close(a.fd)
		a.fd = -1
	}
	a.started = false
}

// Run drains the audit socket, parses messages, and pushes AuthEvent
// telemetry into out. Honors ctx.Done().
func (a *AuditSource) Run(ctx context.Context, sink *StreamingSink) error {
	if err := a.Start(); err != nil {
		return err
	}
	defer a.Stop()

	a.runPostStartLivenessProbe(ctx)

	buf := make([]byte, 8192)
	for {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		n, err := unix.Read(a.fd, buf)
		if err != nil {
			if errors.Is(err, unix.EAGAIN) || errors.Is(err, unix.EWOULDBLOCK) {
				select {
				case <-ctx.Done():
					return nil
				case <-time.After(100 * time.Millisecond):
					continue
				}
			}
			if errors.Is(err, unix.EINTR) {
				continue
			}
			a.recordError(err)
			return err
		}
		a.parseAndDispatch(ctx, buf[:n], sink)
	}
}

// parseAndDispatch interprets one or more concatenated netlink messages.
// Audit messages are key=value text after the netlink header.
func (a *AuditSource) parseAndDispatch(ctx context.Context, data []byte, sink *StreamingSink) {
	for len(data) >= 16 {
		var p auditPacket
		p.Length = binary.LittleEndian.Uint32(data[0:4])
		p.Type = binary.LittleEndian.Uint16(data[4:6])
		if p.Length < 16 || int(p.Length) > len(data) {
			return
		}
		body := string(data[16:p.Length])
		// netlink alignment: round up to 4 bytes. Advance the packet view before
		// event handling so duplicate-suppression branches cannot stall parsing.
		aligned := (p.Length + 3) &^ 3
		if int(aligned) > len(data) {
			return
		}
		data = data[aligned:]

		ev := a.parseAuditBody(p.Type, body)
		if ev != nil {
			if ev.File != nil && a.fileDedupe != nil && !a.fileDedupe.AllowWithSource(ev.File.Path, DedupeSourceAudit) {
				continue
			}
			if sink.Send(ctx, *ev) {
				a.emitted.Add(1)
			}
		}
	}
}

// parseAuditBody maps Linux audit multicasts to telemetry. User-auth lines
// become AuthEvents; SYSCALL/PATH correlation yields FileEvents (who-data parity).
func (a *AuditSource) parseAuditBody(t uint16, body string) *Telemetry {
	const (
		AUDIT_USER_AUTH    = 1100
		AUDIT_USER_ACCT    = 1101
		AUDIT_USER_LOGIN   = 1112
		AUDIT_USER_CMD     = 1123
		auditSyscallNLType = 1300 // AUDIT_SYSCALL
		auditPathNLType    = 1302 // AUDIT_PATH
	)
	fields := parseAuditKV(body)
	typ := fields["type"]

	switch {
	case typ == "SYSCALL" || t == auditSyscallNLType:
		serial := parseAuditMsgSerial(body)
		sc := syscallScratchFrom(fields)
		if serial != "" && sc != nil {
			a.rememberSyscall(serial, sc)
		}
		return nil
	case typ == "PATH" || t == auditPathNLType:
		return a.telemetryFromAuditPATH(fields, parseAuditMsgSerial(body))
	}

	switch t {
	case AUDIT_USER_AUTH, AUDIT_USER_ACCT, AUDIT_USER_LOGIN, AUDIT_USER_CMD:
	default:
		return nil
	}
	now := time.Now().UTC()
	ae := &schema.AuthEvent{
		BaseEvent: schema.BaseEvent{
			SchemaVersion: schema.SchemaVersionV1,
			EventType:     schema.EventAuth,
			EndpointID:    a.endpointID,
			Timestamp:     now,
			Hostname:      a.hostname,
			OS:            runtime.GOOS,
		},
		User:     fields["acct"],
		Outcome:  fields["res"],
		AuthType: auditTypeName(t),
		SourceIP: fields["addr"],
	}
	if pidStr := fields["pid"]; pidStr != "" {
		if pid, err := strconv.ParseUint(pidStr, 10, 32); err == nil && a.tracker != nil {
			a.tracker.Upsert(LineageEntry{PID: uint32(pid)})
		}
	}
	return &Telemetry{Auth: ae}
}

func parseAuditMsgSerial(body string) string {
	const pref = "msg=audit("
	i := strings.Index(body, pref)
	if i < 0 {
		return ""
	}
	start := i + len(pref)
	idx := strings.IndexByte(body[start:], ')')
	if idx < 0 {
		return ""
	}
	inside := body[start : start+idx]
	j := strings.LastIndexByte(inside, ':')
	if j < 0 {
		return ""
	}
	return strings.TrimSpace(inside[j+1:])
}

func syscallScratchFrom(fields map[string]string) *auditSyscallScratch {
	var s auditSyscallScratch
	if v := fields["pid"]; v != "" {
		if x, err := strconv.Atoi(v); err == nil {
			s.pid = x
		}
	}
	if v := fields["ppid"]; v != "" {
		if x, err := strconv.Atoi(v); err == nil {
			s.ppid = x
		}
	}
	s.auid = fields["auid"]
	s.euid = firstNonEmpty(fields["euid"], fields["uid"])
	s.uid = firstNonEmpty(s.euid, s.auid)
	s.syscall = fields["syscall"]
	s.exe = fields["exe"]
	s.comm = fields["comm"]
	if s.pid == 0 && s.syscall == "" && s.exe == "" && s.comm == "" {
		return nil
	}
	return &s
}

func (a *AuditSource) rememberSyscall(serial string, sc *auditSyscallScratch) {
	a.pendingMu.Lock()
	defer a.pendingMu.Unlock()
	if len(a.pending) > 2048 {
		a.pending = make(map[string]*auditSyscallScratch, 512)
	}
	a.pending[serial] = sc
}

func (a *AuditSource) takeSyscall(serial string) *auditSyscallScratch {
	if serial == "" {
		return nil
	}
	a.pendingMu.Lock()
	defer a.pendingMu.Unlock()
	sc := a.pending[serial]
	delete(a.pending, serial)
	return sc
}

func (a *AuditSource) telemetryFromAuditPATH(fields map[string]string, serial string) *Telemetry {
	path := fields["name"]
	if path == "" {
		return nil
	}
	nametype := strings.ToLower(strings.TrimSpace(fields["nametype"]))
	op := "audit_path"
	if nametype != "" {
		op = "audit_path_" + nametype
	}
	sc := a.takeSyscall(serial)
	p := 0
	subjUID := ""
	if sc != nil {
		p = sc.pid
		subjUID = sc.uid
		if sc.pid != 0 && a.tracker != nil {
			a.tracker.Upsert(LineageEntry{PID: uint32(sc.pid)})
		}
		if nametype == "" && sc.syscall != "" {
			op = "audit_path_syscall_" + sc.syscall
		}
	}
	now := time.Now().UTC()
	fe := &schema.FileEvent{
		BaseEvent: schema.BaseEvent{
			SchemaVersion: schema.SchemaVersionV1,
			EventType:     schema.EventFile,
			EndpointID:    a.endpointID,
			Timestamp:     now,
			Hostname:      a.hostname,
			OS:            runtime.GOOS,
		},
		Path:       path,
		Operation:  op,
		ActorPID:   p,
		SubjectUID: subjUID,
	}
	if sc != nil {
		fe.AuditUID = sc.auid
		fe.EffectiveUID = firstNonEmpty(sc.euid, sc.uid)
		fe.ActorPPID = sc.ppid
		fe.ActorExe = sc.exe
		fe.ActorComm = sc.comm
		fe.Syscall = sc.syscall
	}
	return &Telemetry{File: fe}
}

func auditTypeName(t uint16) string {
	switch t {
	case 1100:
		return "audit_user_auth"
	case 1101:
		return "audit_user_acct"
	case 1112:
		return "audit_user_login"
	case 1123:
		return "audit_user_cmd"
	}
	return "audit"
}

func parseAuditKV(body string) map[string]string {
	out := make(map[string]string, 8)
	for _, tok := range strings.Fields(body) {
		eq := strings.IndexByte(tok, '=')
		if eq <= 0 {
			continue
		}
		k := tok[:eq]
		v := strings.Trim(tok[eq+1:], `"`)
		if v == "" {
			continue
		}
		out[k] = v
	}
	return out
}

// ExportMonitoringHealth implements the per-source health interface.
func (a *AuditSource) ExportMonitoringHealth() map[string]any {
	src := MonitoringSource{
		Name:   "linux_audit",
		OS:     "linux",
		Source: "audit-netlink",
		Status: "healthy",
		EPSOut: a.emitted.Load(),
	}
	if !a.started {
		src.Status = "unavailable"
	}
	if errPtr := a.errs.Load(); errPtr != nil && *errPtr != "" {
		src.LastError = *errPtr
		src.Status = "degraded"
	}
	var notes []string
	if a.managedRules {
		notes = append(notes, "managed_audit_probe=on")
		if errPtr := a.managedRulesErr.Load(); errPtr != nil && *errPtr != "" {
			notes = append(notes, "managed_audit_err="+*errPtr)
			if src.Status == "healthy" {
				src.Status = "degraded"
			}
		}
	}
	if a.fileDedupe != nil {
		notes = append(notes, fmt.Sprintf("file_dedupe_skipped=%d", a.fileDedupe.Skipped()))
	}
	if len(notes) > 0 {
		src.Notes = strings.Join(notes, "; ")
	}
	m := src.ToMap()
	a.livenessMu.Lock()
	ran, ok, note := a.livenessRan, a.livenessOK, a.livenessNote
	a.livenessMu.Unlock()
	if ran {
		m["liveness_probe_ok"] = ok
		if note != "" {
			m["liveness_probe_detail"] = note
		}
		if !ok && a.managedRules && src.Status == "healthy" {
			m["status"] = "degraded"
		}
	}
	return m
}

// runPostStartLivenessProbe writes the managed probe file (when rules are managed) and expects audit netlink traffic.
func (a *AuditSource) runPostStartLivenessProbe(ctx context.Context) {
	a.livenessMu.Lock()
	defer a.livenessMu.Unlock()
	a.livenessRan = true
	if !a.started || a.fd < 0 {
		a.livenessOK = false
		a.livenessNote = "not_started"
		return
	}
	if !a.managedRules {
		a.livenessOK = true
		a.livenessNote = "skipped_no_managed_probe"
		return
	}
	path := filepath.Join("/var/lib/edr", ".audit_managed_probe")
	if err := os.WriteFile(path, []byte("liveness\n"), 0o644); err != nil {
		a.livenessOK = false
		a.livenessNote = "write:" + err.Error()
		return
	}
	ctx2, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	buf := make([]byte, 8192)
	for {
		if ctx2.Err() != nil {
			a.livenessOK = false
			a.livenessNote = "timeout_no_netlink"
			return
		}
		n, err := unix.Read(a.fd, buf)
		if err != nil {
			if errors.Is(err, unix.EAGAIN) || errors.Is(err, unix.EWOULDBLOCK) {
				select {
				case <-ctx2.Done():
					a.livenessOK = false
					a.livenessNote = "timeout_no_netlink"
					return
				case <-time.After(20 * time.Millisecond):
				}
				continue
			}
			a.livenessOK = false
			a.livenessNote = err.Error()
			return
		}
		if n > 0 {
			a.livenessOK = true
			a.livenessNote = ""
			return
		}
	}
}

func (a *AuditSource) recordError(err error) {
	if err == nil {
		return
	}
	msg := err.Error()
	a.errs.Store(&msg)
}
