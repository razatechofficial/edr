//go:build linux

package collector

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
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
// It provides who-data style file access telemetry and a
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
}

type auditSyscallScratch struct {
	pid     int
	uid     string
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
func NewAuditSource(endpointID, hostname string, tracker *LineageTracker) *AuditSource {
	if hostname == "" {
		if h, err := os.Hostname(); err == nil {
			hostname = h
		} else {
			hostname = "unknown"
		}
	}
	return &AuditSource{
		endpointID: endpointID,
		hostname:   hostname,
		tracker:    tracker,
		fd:         -1,
		pending:    make(map[string]*auditSyscallScratch),
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
		ev := a.parseAuditBody(p.Type, body)
		if ev != nil {
			if sink.Send(ctx, *ev) {
				a.emitted.Add(1)
			}
		}
		// netlink alignment: round up to 4 bytes.
		aligned := (p.Length + 3) &^ 3
		if int(aligned) > len(data) {
			return
		}
		data = data[aligned:]
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
	s.uid = firstNonEmpty(fields["uid"], fields["euid"])
	if s.uid == "" {
		s.uid = fields["auid"]
	}
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
	return src.ToMap()
}

func (a *AuditSource) recordError(err error) {
	if err == nil {
		return
	}
	msg := err.Error()
	a.errs.Store(&msg)
}
