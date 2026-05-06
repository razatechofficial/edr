//go:build linux

package kernel

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/razatechofficial/edr/pkg/events"
)

const (
	bpfCommLen         = 16
	bpfFilenameLen     = 256
	bpfArgsLen         = 512
	bpfObjectPathDefault = "/var/lib/edr/bpf/edr.bpf.o"
	rawHeaderSize      = 26
	bpfEvtProcExec     = 1
	bpfEvtProcExit     = 2
	bpfEvtProcFork     = 3
	bpfEvtFileOpen     = 6
	bpfEvtFileWrite    = 7
	bpfEvtFileDel      = 8
	bpfEvtFileRen      = 9
	bpfEvtFileChmod    = 28
	bpfEvtBPFLoad      = 29
	bpfEvtBPFMapAccess = 30
	bpfEvtCgroupAttach = 31
	bpfEvtCgroupMkdir  = 32
	bpfEvtSeccomp      = 33
	bpfEvtProcMemWrite = 34
	bpfEvtDNSQuery     = 35
	bpfEvtNetConn      = 11
	bpfEvtNetAccept    = 12
	bpfEvtNetBind      = 13
	bpfEvtNetClose     = 14
	bpfEvtModule       = 22
	bpfEvtMount        = 23
	bpfEvtPtrace       = 24
	bpfEvtSignal       = 25
	bpfEvtUnshare      = 26
	bpfEvtMadvise      = 27
)

// bpfBytecode holds embedded eBPF bytecode when compiled with `make ebpf-link`
// and the bpf/ directory exists. Build with -tags embed_ebpf to activate.
// The default empty slice causes loadCollection to fall back to the on-disk path.
var bpfBytecode []byte

// bpfProcessEvent mirrors the C struct process_event emitted by the eBPF program.
type bpfProcessEvent struct {
	Type     uint32
	PID      uint32
	PPID     uint32
	UID      uint32
	GID      uint32
	TS       uint64
	Comm     [bpfCommLen]byte
	Filename [bpfFilenameLen]byte
	ArgsSize uint32
	Args     [bpfArgsLen]byte
	ExitCode int32
	ChildPID uint32
	CloneFlg uint64
}

// bpfFileEvent mirrors the C struct file_event emitted by the eBPF program.
type bpfFileEvent struct {
	Type          uint32
	PID           uint32
	PPID          uint32
	UID           uint32
	GID           uint32
	TS            uint64
	Comm          [bpfCommLen]byte
	Filename      [bpfFilenameLen]byte
	Flags         uint32
	WriteFD       uint32
	Mode          uint32
	_             uint32 // C reserved_align before bytes_written
	BytesW        uint64
	SensitivePath uint8
	_             [7]byte
	NewName       [bpfFilenameLen]byte
}

// bpfEventHeader mirrors event_header in platform/linux/ebpf/common.h.
type bpfEventHeader struct {
	Type uint32
	PID  uint32
	PPID uint32
	UID  uint32
	GID  uint32
	TS   uint64
	Comm [bpfCommLen]byte
}

// bpfSecurityEvent mirrors struct security_event (with padding before arg0).
type bpfSecurityEvent struct {
	Hdr         bpfEventHeader
	SysNr       uint32
	_           uint32
	Arg0        uint64
	Arg1        uint64
	Arg2        uint64
	BPFCmd      uint32
	BPFProgType uint32
	BPFMapID    uint32
	Mode        uint32
	Path        [bpfFilenameLen]byte
	MapName     [64]byte
}

// bpfNetworkEvent mirrors the C struct network_event emitted by the eBPF program.
type bpfNetworkEvent struct {
	Type     uint32
	PID      uint32
	PPID     uint32
	UID      uint32
	GID      uint32
	TS       uint64
	Comm     [bpfCommLen]byte
	Proto    uint32
	SrcAddr  uint32
	SrcPort  uint16
	DstAddr  uint32
	DstPort  uint16
	SrcAddr6 [16]byte
	DstAddr6 [16]byte
	IsIPv6   uint8
	Dir      uint8
	DNSQuery [254]byte
	DNSQType uint16
}

// EBPFDriver implements Driver using eBPF tracepoints and ring buffers on Linux.
type EBPFDriver struct {
	agentID   string
	mu        sync.RWMutex
	policy    EventPolicy
	startTime time.Time

	coll       *ebpf.Collection
	links      []link.Link
	ownProgIDs []uint32
	reader     *ringbuf.Reader
	readers    []*ringbuf.Reader

	rootCtx     context.Context
	rootCancel  context.CancelFunc
	eventCtx    context.Context
	eventCancel context.CancelFunc
	wg          sync.WaitGroup
	running     atomic.Bool
	buf         *RingBuffer

	received  atomic.Uint64
	dropped   atomic.Uint64
	processed atomic.Uint64
	errors    atomic.Uint64
	features  linuxFeatureSet

	bpfObjectPath string // optional override; empty uses bpfObjectPathDefault
	bpfPinPath    string // optional bpffs pin directory for maps

	loadDiagMu sync.RWMutex
	loadDiag   string // last ebpf load / verifier diagnostic (best-effort)

	tamperEvents            atomic.Uint64 // ebpf watchdog "program missing" signals
	programReattachAttempts atomic.Uint64
	programReattachFailures atomic.Uint64
	lastReattachUnix        atomic.Int64
	reattachMu              sync.Mutex // serializes reattach vs concurrent paths

	tamperByProgMu sync.Mutex
	tamperByProg   map[uint32]uint64 // per-program missing detections
}

type linuxFeatureSet struct {
	HasBTF       bool
	HasBPFLSM    bool
	HasCgroupBPF bool
	KernelMajor  int
	KernelMinor  int
}

// NewEBPFDriver creates a new eBPF-based kernel driver. Requires root privileges.
// objectPathOverride, when non-empty, replaces the default /var/lib/edr/bpf/edr.bpf.o path.
func NewEBPFDriver(agentID string, objectPathOverride string) (*EBPFDriver, error) {
	if os.Getuid() != 0 {
		return nil, fmt.Errorf("ebpf driver requires root privileges")
	}
	return &EBPFDriver{
		agentID:       agentID,
		policy:        DefaultPolicy(),
		bpfObjectPath: objectPathOverride,
	}, nil
}

// SetBPFPinPath configures bpffs pinning for map objects (call before Start).
func (d *EBPFDriver) SetBPFPinPath(path string) {
	if d == nil {
		return
	}
	d.mu.Lock()
	d.bpfPinPath = strings.TrimSpace(path)
	d.mu.Unlock()
}

// LastLoadDiagnostics returns the most recent collection attach diagnostic text (verifier/kernel loader).
func (d *EBPFDriver) LastLoadDiagnostics() string {
	if d == nil {
		return ""
	}
	d.loadDiagMu.RLock()
	defer d.loadDiagMu.RUnlock()
	return d.loadDiag
}

// TamperMetrics surfaces anti-tamper counters consumed by monitoring_health.json.
func (d *EBPFDriver) TamperMetrics() map[string]any {
	if d == nil {
		return nil
	}
	m := map[string]any{
		"ebpf_program_missing_events": d.tamperEvents.Load(),
		"program_reattach_attempts":   d.programReattachAttempts.Load(),
		"program_reattach_failures":     d.programReattachFailures.Load(),
	}
	if ts := d.lastReattachUnix.Load(); ts > 0 {
		m["last_reattach_unix"] = ts
	}
	d.tamperByProgMu.Lock()
	if len(d.tamperByProg) > 0 {
		cp := make(map[string]uint64, len(d.tamperByProg))
		for id, n := range d.tamperByProg {
			cp[fmt.Sprintf("%d", id)] = n
		}
		m["ebpf_program_tamper_by_id"] = cp
	}
	d.tamperByProgMu.Unlock()
	return m
}

func (d *EBPFDriver) setLoadDiag(msg string) {
	if d == nil {
		return
	}
	d.loadDiagMu.Lock()
	d.loadDiag = msg
	d.loadDiagMu.Unlock()
}

// Name returns the driver identifier.
func (d *EBPFDriver) Name() string { return "ebpf" }

// Capabilities reports which event types this driver can collect.
func (d *EBPFDriver) Capabilities() []events.EventType {
	return []events.EventType{
		events.EventProcess,
		events.EventFile,
		events.EventNetwork,
		events.EventMemory,
		events.EventModule,
		events.EventMount,
		events.EventSignal,
		events.EventNamespace,
	}
}

// Start loads eBPF programs, attaches tracepoints, and begins event collection.
func (d *EBPFDriver) Start(ctx context.Context, buf *RingBuffer) error {
	if d.running.Load() {
		return fmt.Errorf("ebpf driver already running")
	}

	d.buf = buf
	d.features = probeLinuxFeatures()

	rootCtx, rootCancel := context.WithCancel(ctx)
	d.rootCtx = rootCtx
	d.rootCancel = rootCancel
	evCtx, evCancel := context.WithCancel(rootCtx)
	d.eventCtx = evCtx
	d.eventCancel = evCancel

	if err := d.bootstrapLoadedCollection(); err != nil {
		d.cleanup()
		rootCancel()
		d.rootCtx = nil
		d.rootCancel = nil
		d.eventCtx = nil
		d.eventCancel = nil
		return err
	}

	d.startTime = time.Now()
	d.running.Store(true)
	d.collectOwnProgramIDs()
	_ = d.emitFeatureStatusEvent()

	d.wg.Add(len(d.readers))
	for _, r := range d.readers {
		go d.eventLoop(evCtx, r)
	}
	go d.watchdogLoop(rootCtx)

	return nil
}

// bootstrapLoadedCollection loads the BPF object, attaches tracepoints, opens ringbuf readers, and syncs policy.
func (d *EBPFDriver) bootstrapLoadedCollection() error {
	spec, err := d.loadCollection()
	if err != nil {
		d.setLoadDiag(err.Error())
		return fmt.Errorf("loading ebpf collection: %w", err)
	}

	d.mu.RLock()
	pinPath := d.bpfPinPath
	d.mu.RUnlock()
	if pinPath != "" {
		if mkErr := os.MkdirAll(pinPath, 0o755); mkErr != nil {
			d.captureVerifierDiag(mkErr)
			return fmt.Errorf("bpffs pin path mkdir %s: %w", pinPath, mkErr)
		}
	}

	opts := ebpf.CollectionOptions{
		Programs: ebpf.ProgramOptions{
			LogLevel: ebpf.LogLevelBranch,
		},
	}
	if pinPath != "" {
		opts.Maps.PinPath = pinPath
	}

	coll, err := ebpf.NewCollectionWithOptions(spec, opts)
	if err != nil {
		d.captureVerifierDiag(err)
		return fmt.Errorf("creating ebpf collection: %w", err)
	}
	d.setLoadDiag("")
	d.coll = coll

	if err := d.attachTracepoints(); err != nil {
		d.cleanup()
		return fmt.Errorf("attaching tracepoints: %w", err)
	}

	if err := d.openReaders(); err != nil {
		d.cleanup()
		return err
	}

	if err := d.syncPolicyToMaps(); err != nil {
		d.cleanup()
		return fmt.Errorf("syncing initial policy: %w", err)
	}
	return nil
}

// Stop detaches all eBPF hooks, closes the reader, and releases resources.
func (d *EBPFDriver) Stop() error {
	if !d.running.CompareAndSwap(true, false) {
		return nil
	}
	if d.rootCancel != nil {
		d.rootCancel()
	}
	for _, r := range d.readers {
		if r != nil {
			_ = r.Close()
		}
	}
	d.wg.Wait()
	d.cleanup()
	d.rootCtx = nil
	d.rootCancel = nil
	d.eventCtx = nil
	d.eventCancel = nil
	return nil
}

// reattachWithBoundedRetry tears down the current collection (without stopping the watchdog),
// reloads programs, reattaches tracepoints, and restarts ringbuf reader loops.
func (d *EBPFDriver) reattachWithBoundedRetry(maxAttempts int) error {
	if d == nil || maxAttempts <= 0 {
		return nil
	}
	if !d.running.Load() {
		return nil
	}

	d.reattachMu.Lock()
	defer d.reattachMu.Unlock()

	if !d.running.Load() {
		return nil
	}

	var lastErr error
	for attempt := 0; attempt < maxAttempts; attempt++ {
		d.programReattachAttempts.Add(1)
		var err error
		if testEbpfReattachOverride != nil {
			err = testEbpfReattachOverride(d, attempt)
		} else {
			err = d.reattachOnce()
		}
		if err != nil {
			lastErr = err
			d.programReattachFailures.Add(1)
			backoff := time.Duration(attempt+1) * 200 * time.Millisecond
			time.Sleep(backoff)
			continue
		}
		d.lastReattachUnix.Store(time.Now().Unix())
		d.collectOwnProgramIDs()
		return nil
	}
	return lastErr
}

func (d *EBPFDriver) reattachOnce() error {
	if d.rootCtx == nil || d.eventCancel == nil {
		return fmt.Errorf("ebpf driver event context not initialized")
	}
	// Stop reader goroutines only; keep rootCtx alive for watchdog.
	d.eventCancel()
	for _, r := range d.readers {
		if r != nil {
			_ = r.Close()
		}
	}
	d.wg.Wait()

	d.cleanup()

	evCtx, evCancel := context.WithCancel(d.rootCtx)
	d.eventCtx = evCtx
	d.eventCancel = evCancel

	if err := d.bootstrapLoadedCollection(); err != nil {
		return err
	}

	d.wg.Add(len(d.readers))
	for _, r := range d.readers {
		go d.eventLoop(evCtx, r)
	}
	return nil
}

// test-only hook: if set, reattachWithBoundedRetry delegates here.
var testEbpfReattachOverride func(d *EBPFDriver, maxAttempts int) error

// SetPolicy updates the event collection policy by writing to eBPF maps.
func (d *EBPFDriver) SetPolicy(policy EventPolicy) error {
	d.mu.Lock()
	d.policy = policy
	d.mu.Unlock()

	if d.running.Load() {
		return d.syncPolicyToMaps()
	}
	return nil
}

// Stats returns current driver metrics.
func (d *EBPFDriver) Stats() DriverStats {
	var uptime float64
	if !d.startTime.IsZero() {
		uptime = time.Since(d.startTime).Seconds()
	}
	return DriverStats{
		EventsReceived:  d.received.Load(),
		EventsDropped:   d.dropped.Load(),
		EventsProcessed: d.processed.Load(),
		UptimeSeconds:   uptime,
		ErrorCount:      d.errors.Load(),
	}
}

func (d *EBPFDriver) cleanup() {
	for _, l := range d.links {
		l.Close()
	}
	d.links = nil
	if d.reader != nil {
		d.reader.Close()
		d.reader = nil
	}
	for _, r := range d.readers {
		r.Close()
	}
	d.readers = nil
	if d.coll != nil {
		d.coll.Close()
		d.coll = nil
	}
}

func (d *EBPFDriver) captureVerifierDiag(err error) {
	if err == nil {
		return
	}
	var ve *ebpf.VerifierError
	if errors.As(err, &ve) {
		d.setLoadDiag(ve.Error())
		return
	}
	d.setLoadDiag(err.Error())
}

func (d *EBPFDriver) resolvedBPFObjectPath() string {
	if d.bpfObjectPath != "" {
		return d.bpfObjectPath
	}
	return bpfObjectPathDefault
}

func (d *EBPFDriver) loadCollection() (*ebpf.CollectionSpec, error) {
	if len(bpfBytecode) > 0 {
		return ebpf.LoadCollectionSpecFromReader(bytes.NewReader(bpfBytecode))
	}
	path := d.resolvedBPFObjectPath()
	if err := d.verifyBPFObjectVersionFile(path); err != nil {
		return nil, err
	}
	if _, err := os.Stat(path); err != nil {
		return nil, fmt.Errorf(
			"ebpf object not found at %s (compile with 'make ebpf-link' or build with -tags embed_ebpf): %w",
			path, err,
		)
	}
	return ebpf.LoadCollectionSpec(path)
}

func (d *EBPFDriver) verifyBPFObjectVersionFile(objectPath string) error {
	want := ebpfExpectedObjectVersion()
	if want == "" {
		return nil
	}
	verPath := objectPath + ".version"
	data, err := os.ReadFile(verPath)
	if err != nil {
		return nil
	}
	got := strings.TrimSpace(string(data))
	if got != want {
		return fmt.Errorf("bpf object version %q in %s does not match agent %q; run `make ebpf-install` or reinstall the bpf package", got, verPath, want)
	}
	return nil
}

func (d *EBPFDriver) attachTracepoints() error {
	for name, prog := range d.coll.Programs {
		if prog == nil {
			continue
		}
		const prefix = "tracepoint__"
		if len(name) <= len(prefix) || name[:len(prefix)] != prefix {
			continue
		}
		rest := name[len(prefix):]
		sep := -1
		for i := 0; i+1 < len(rest); i++ {
			if rest[i] == '_' && rest[i+1] == '_' {
				sep = i
				break
			}
		}
		if sep <= 0 || sep+2 >= len(rest) {
			continue
		}
		group := rest[:sep]
		tp := rest[sep+2:]
		if !d.features.HasCgroupBPF && group == "cgroup" {
			continue
		}
		l, err := link.Tracepoint(group, tp, prog, nil)
		if err != nil {
			if isOptionalTracepointAttachFailure(group, tp, err) {
				fmt.Fprintf(os.Stderr, "WARN ebpf: skipping optional tracepoint %s/%s: %v\n", group, tp, err)
				continue
			}
			return fmt.Errorf("attaching %s (%s/%s): %w", name, group, tp, err)
		}
		d.links = append(d.links, l)
	}
	if len(d.links) == 0 {
		return fmt.Errorf("no tracepoints attached; verify ebpf programs are present")
	}
	return nil
}

func isOptionalTracepointAttachFailure(group, tp string, err error) bool {
	// Some hardened kernels can deny this tracepoint perf link despite root + capabilities.
	if group == "syscalls" && tp == "sys_enter_fchmodat" {
		return true
	}
	return false
}

func (d *EBPFDriver) syncPolicyToMaps() error {
	d.mu.RLock()
	p := d.policy
	d.mu.RUnlock()

	if m, ok := d.coll.Maps["policy_config"]; ok {
		var flags uint64
		if p.ProcessEvents {
			flags |= 1 << 0
		}
		if p.FileEvents {
			flags |= 1 << 1
		}
		if p.NetworkEvents {
			flags |= 1 << 2
		}
		if p.MemoryEvents {
			flags |= 1 << 3
		}
		if p.ModuleEvents {
			flags |= 1 << 4
		}
		if p.MountEvents {
			flags |= 1 << 5
		}
		if p.SignalEvents {
			flags |= 1 << 6
		}
		if err := m.Put(uint32(0), flags); err != nil {
			return fmt.Errorf("updating policy_config map: %w", err)
		}
	}

	if m, ok := d.coll.Maps["mute_pids"]; ok {
		for _, pid := range p.MutePIDs {
			if err := m.Put(pid, uint8(1)); err != nil {
				return fmt.Errorf("muting pid %d: %w", pid, err)
			}
		}
	}
	return nil
}

func (d *EBPFDriver) eventLoop(ctx context.Context, reader *ringbuf.Reader) {
	defer d.wg.Done()
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		record, err := reader.Read()
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			d.errors.Add(1)
			continue
		}
		d.received.Add(1)
		if err := d.processRecord(record.RawSample); err != nil {
			d.dropped.Add(1)
			d.errors.Add(1)
			continue
		}
		d.processed.Add(1)
	}
}

func (d *EBPFDriver) processRecord(raw []byte) error {
	if len(raw) < 4 {
		return fmt.Errorf("record too short: %d bytes", len(raw))
	}
	typ := binary.LittleEndian.Uint32(raw[:4])

	d.mu.RLock()
	p := d.policy
	d.mu.RUnlock()

	switch typ {
	case bpfEvtProcExec, bpfEvtProcExit, bpfEvtProcFork:
		if !p.ProcessEvents {
			return nil
		}
		return d.decodeProcessEvent(raw)
	case bpfEvtFileOpen, bpfEvtFileWrite, bpfEvtFileDel, bpfEvtFileRen, bpfEvtFileChmod:
		if !p.FileEvents {
			return nil
		}
		return d.decodeFileEvent(raw)
	case bpfEvtNetConn, bpfEvtNetAccept, bpfEvtNetBind, bpfEvtNetClose:
		if !p.NetworkEvents {
			return nil
		}
		return d.decodeNetworkEvent(raw)
	case bpfEvtDNSQuery:
		if !p.DNSEvents {
			return nil
		}
		return d.decodeDNSQueryEvent(raw)
	case bpfEvtModule:
		if !p.ModuleEvents {
			return nil
		}
		return d.decodeSecurityEvent(raw, events.EventModule)
	case bpfEvtMount:
		if !p.MountEvents {
			return nil
		}
		return d.decodeSecurityEvent(raw, events.EventMount)
	case bpfEvtPtrace, bpfEvtSignal:
		if !p.SignalEvents {
			return nil
		}
		return d.decodeSecurityEvent(raw, events.EventSignal)
	case bpfEvtUnshare:
		if !p.ProcessEvents {
			return nil
		}
		return d.decodeLinuxNamespaceEvent(raw)
	case bpfEvtMadvise:
		if !p.ProcessEvents {
			return nil
		}
		return d.decodeLinuxMadviseEvent(raw)
	case bpfEvtBPFLoad, bpfEvtBPFMapAccess, bpfEvtCgroupAttach, bpfEvtCgroupMkdir, bpfEvtSeccomp:
		return d.decodeAdvancedSecurityEvent(raw)
	case bpfEvtProcMemWrite:
		return d.decodeProcMemWriteEvent(raw)
	default:
		return fmt.Errorf("unknown bpf event type %d", typ)
	}
}

func (d *EBPFDriver) decodeProcessEvent(data []byte) error {
	const sz = unsafe.Sizeof(bpfProcessEvent{})
	if uintptr(len(data)) < sz {
		return fmt.Errorf("process event truncated: got %d, want %d", len(data), sz)
	}

	evt := (*bpfProcessEvent)(unsafe.Pointer(&data[0]))
	payload := make([]byte, 0, 1024)
	payload = appendUint32(payload, evt.PPID)
	payload = appendString(payload, nullTerminated(evt.Filename[:]))
	payload = appendString(payload, nullTerminated(evt.Args[:min(int(evt.ArgsSize), bpfArgsLen)]))
	payload = appendString(payload, "")
	payload = appendString(payload, nullTerminated(evt.Comm[:]))
	if evt.Type == bpfEvtProcExit {
		payload = payload[:0]
		payload = appendInt32(payload, evt.ExitCode)
		payload = appendInt32(payload, 0)
		payload = appendUint64(payload, uint64(evt.TS))
	} else if evt.Type == bpfEvtProcFork {
		payload = payload[:0]
		payload = appendUint32(payload, evt.ChildPID)
		payload = appendUint64(payload, evt.CloneFlg)
	}
	return d.writeRawEvent(uint16(evt.Type), evt, payload)
}

func (d *EBPFDriver) decodeFileEvent(data []byte) error {
	const sz = unsafe.Sizeof(bpfFileEvent{})
	if uintptr(len(data)) < sz {
		return fmt.Errorf("file event truncated: got %d, want %d", len(data), sz)
	}

	evt := (*bpfFileEvent)(unsafe.Pointer(&data[0]))
	payload := make([]byte, 0, 768)
	switch evt.Type {
	case bpfEvtFileOpen:
		payload = appendString(payload, nullTerminated(evt.Filename[:]))
		payload = appendUint32(payload, evt.Flags)
	case bpfEvtFileWrite:
		payload = appendString(payload, nullTerminated(evt.Filename[:]))
		payload = appendUint64(payload, evt.BytesW)
		payload = appendUint32(payload, evt.WriteFD)
	case bpfEvtFileDel:
		payload = appendString(payload, nullTerminated(evt.Filename[:]))
	case bpfEvtFileRen:
		payload = appendString(payload, nullTerminated(evt.Filename[:]))
		payload = appendString(payload, nullTerminated(evt.NewName[:]))
	case bpfEvtFileChmod:
		payload = appendString(payload, nullTerminated(evt.Filename[:]))
		payload = appendUint32(payload, evt.Mode)
		payload = appendUint32(payload, evt.Flags)
	}
	if evt.SensitivePath != 0 {
		payload = append(payload, []byte("|sensitive")...)
	}
	return d.writeRawEvent(uint16(evt.Type), evt, payload)
}

func (d *EBPFDriver) decodeNetworkEvent(data []byte) error {
	const sz = unsafe.Sizeof(bpfNetworkEvent{})
	if uintptr(len(data)) < sz {
		return fmt.Errorf("network event truncated: got %d, want %d", len(data), sz)
	}

	evt := (*bpfNetworkEvent)(unsafe.Pointer(&data[0]))
	payload := make([]byte, 0, 128)
	family := uint8(2)
	if evt.IsIPv6 == 1 {
		family = 10
	}
	payload = append(payload, family)
	payload = append(payload, uint8(evt.Proto))
	payload = append(payload, evt.Dir)
	if evt.IsIPv6 == 1 {
		payload = append(payload, evt.SrcAddr6[:]...)
	} else {
		payload = append(payload, ipv4Bytes(evt.SrcAddr)...)
	}
	payload = appendUint16(payload, evt.SrcPort)
	if evt.IsIPv6 == 1 {
		payload = append(payload, evt.DstAddr6[:]...)
	} else {
		payload = append(payload, ipv4Bytes(evt.DstAddr)...)
	}
	payload = appendUint16(payload, evt.DstPort)
	return d.writeRawEvent(uint16(evt.Type), evt, payload)
}

func (d *EBPFDriver) decodeLinuxNamespaceEvent(data []byte) error {
	const sz = unsafe.Sizeof(bpfSecurityEvent{})
	if uintptr(len(data)) < sz {
		return fmt.Errorf("namespace event truncated: got %d, want >= %d", len(data), sz)
	}
	se := (*bpfSecurityEvent)(unsafe.Pointer(&data[0]))
	env := map[string]interface{}{
		"type":          events.EventNamespace,
		"timestamp":     time.Now().UTC(),
		"agent_id":      d.agentID,
		"pid":           se.Hdr.PID,
		"unshare_flags": se.Arg0,
		"process_name":  nullTerminated(se.Hdr.Comm[:]),
	}
	return d.writeJSONEvent(env)
}

func (d *EBPFDriver) decodeLinuxMadviseEvent(data []byte) error {
	const sz = unsafe.Sizeof(bpfSecurityEvent{})
	if uintptr(len(data)) < sz {
		return fmt.Errorf("madvise event truncated: got %d, want >= %d", len(data), sz)
	}
	se := (*bpfSecurityEvent)(unsafe.Pointer(&data[0]))
	env := map[string]interface{}{
		"type":           "madvise",
		"timestamp":      time.Now().UTC(),
		"agent_id":       d.agentID,
		"pid":            se.Hdr.PID,
		"madvise_advice": int32(se.Arg2),
		"madvise_addr":   se.Arg0,
		"madvise_len":    se.Arg1,
		"process_name":   nullTerminated(se.Hdr.Comm[:]),
	}
	return d.writeJSONEvent(env)
}

func (d *EBPFDriver) decodeSecurityEvent(data []byte, et events.EventType) error {
	var pid uint32
	if len(data) >= 8 {
		pid = binary.LittleEndian.Uint32(data[4:8])
	}
	evType := et
	if et == events.EventSignal && len(data) >= 4 {
		switch binary.LittleEndian.Uint32(data[0:4]) {
		case bpfEvtPtrace:
			evType = events.EventPtrace
		case bpfEvtSignal:
			evType = events.EventSignal
		}
	}
	envelope := map[string]interface{}{
		"type":       evType,
		"timestamp":  time.Now().UTC(),
		"agent_id":   d.agentID,
		"pid":        pid,
		"event_kind": string(et),
	}
	return d.writeJSONEvent(envelope)
}

func (d *EBPFDriver) decodeAdvancedSecurityEvent(data []byte) error {
	const sz = unsafe.Sizeof(bpfSecurityEvent{})
	if uintptr(len(data)) < sz {
		return fmt.Errorf("security event truncated: got %d, want >= %d", len(data), sz)
	}
	se := (*bpfSecurityEvent)(unsafe.Pointer(&data[0]))
	operation := "security"
	switch se.Hdr.Type {
	case bpfEvtBPFLoad:
		operation = "bpf_load"
	case bpfEvtBPFMapAccess:
		operation = "bpf_map_access"
	case bpfEvtCgroupAttach:
		operation = "cgroup_attach"
	case bpfEvtCgroupMkdir:
		operation = "cgroup_mkdir"
	case bpfEvtSeccomp:
		operation = "seccomp_filter_install"
	}
	env := map[string]interface{}{
		"type":          "process",
		"timestamp":     time.Now().UTC(),
		"agent_id":      d.agentID,
		"pid":           se.Hdr.PID,
		"operation":     operation,
		"path":          nullTerminated(se.Path[:]),
		"bpf_cmd":       se.BPFCmd,
		"bpf_prog_type": se.BPFProgType,
		"bpf_map_id":    se.BPFMapID,
		"bpf_map_name":  nullTerminated(se.MapName[:]),
	}
	return d.writeJSONEvent(env)
}

func (d *EBPFDriver) decodeProcMemWriteEvent(data []byte) error {
	const sz = unsafe.Sizeof(bpfFileEvent{})
	if uintptr(len(data)) < sz {
		return fmt.Errorf("proc_mem event truncated: got %d, want >= %d", len(data), sz)
	}
	fe := (*bpfFileEvent)(unsafe.Pointer(&data[0]))
	env := map[string]interface{}{
		"type":       "injection",
		"timestamp":  time.Now().UTC(),
		"agent_id":   d.agentID,
		"source_pid": fe.PID,
		"target_pid": fe.PID,
		"technique":  "proc_mem_write",
		"path":       nullTerminated(fe.Filename[:]),
	}
	return d.writeJSONEvent(env)
}

func (d *EBPFDriver) decodeDNSQueryEvent(data []byte) error {
	const sz = unsafe.Sizeof(bpfNetworkEvent{})
	if uintptr(len(data)) < sz {
		return fmt.Errorf("dns event truncated: got %d, want >= %d", len(data), sz)
	}
	ne := (*bpfNetworkEvent)(unsafe.Pointer(&data[0]))
	env := map[string]interface{}{
		"type":      "dns",
		"timestamp": time.Now().UTC(),
		"agent_id":  d.agentID,
		"pid":       ne.PID,
		"query":     nullTerminated(ne.DNSQuery[:]),
		"dns_type":  ne.DNSQType,
	}
	return d.writeJSONEvent(env)
}

func (d *EBPFDriver) writeRawEvent(typ uint16, hdr interface{}, payload []byte) error {
	var pid, uid, gid, tid uint32
	var ts uint64
	switch e := hdr.(type) {
	case *bpfProcessEvent:
		pid, uid, gid, ts = e.PID, e.UID, e.GID, e.TS
		tid = e.PID
	case *bpfFileEvent:
		pid, uid, gid, ts = e.PID, e.UID, e.GID, e.TS
		tid = e.PID
	case *bpfNetworkEvent:
		pid, uid, gid, ts = e.PID, e.UID, e.GID, e.TS
		tid = e.PID
	}
	raw := make([]byte, rawHeaderSize+len(payload))
	binary.LittleEndian.PutUint16(raw[0:2], typ)
	binary.LittleEndian.PutUint64(raw[2:10], ts)
	binary.LittleEndian.PutUint32(raw[10:14], pid)
	binary.LittleEndian.PutUint32(raw[14:18], tid)
	binary.LittleEndian.PutUint32(raw[18:22], uid)
	binary.LittleEndian.PutUint32(raw[22:26], gid)
	copy(raw[26:], payload)
	return d.buf.Write(raw)
}

func (d *EBPFDriver) writeJSONEvent(envelope map[string]interface{}) error {
	data, err := json.Marshal(envelope)
	if err != nil {
		return fmt.Errorf("marshaling event: %w", err)
	}
	return d.buf.Write(data)
}

func probeLinuxFeatures() linuxFeatureSet {
	f := linuxFeatureSet{
		HasBTF:       fileExists("/sys/kernel/btf/vmlinux"),
		HasBPFLSM:    fileExists("/sys/kernel/security/lsm") && strings.Contains(readFileOrEmpty("/sys/kernel/security/lsm"), "bpf"),
		HasCgroupBPF: fileExists("/sys/fs/cgroup"),
	}
	rel := strings.TrimSpace(readFileOrEmpty("/proc/sys/kernel/osrelease"))
	parts := strings.Split(rel, ".")
	if len(parts) >= 2 {
		f.KernelMajor, _ = strconv.Atoi(parts[0])
		minor := parts[1]
		if i := strings.IndexByte(minor, '-'); i > 0 {
			minor = minor[:i]
		}
		f.KernelMinor, _ = strconv.Atoi(minor)
	}
	return f
}

func (d *EBPFDriver) emitFeatureStatusEvent() error {
	env := map[string]interface{}{
		"type":           "feature_status",
		"timestamp":      time.Now().UTC(),
		"agent_id":       d.agentID,
		"has_btf":        boolToInt(d.features.HasBTF),
		"has_bpf_lsm":    boolToInt(d.features.HasBPFLSM),
		"has_cgroup_bpf": boolToInt(d.features.HasCgroupBPF),
		"kernel_version": fmt.Sprintf("%d.%d", d.features.KernelMajor, d.features.KernelMinor),
	}
	return d.writeJSONEvent(env)
}

func boolToInt(v bool) int {
	if v {
		return 1
	}
	return 0
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func readFileOrEmpty(path string) string {
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return string(b)
}

func nullTerminated(b []byte) string {
	for i, c := range b {
		if c == 0 {
			return string(b[:i])
		}
	}
	return string(b)
}

func uint32ToIPv4(addr uint32) string {
	return fmt.Sprintf("%d.%d.%d.%d",
		addr&0xFF, (addr>>8)&0xFF, (addr>>16)&0xFF, (addr>>24)&0xFF)
}

func ipv4Bytes(addr uint32) []byte {
	ip := net.IPv4(byte(addr), byte(addr>>8), byte(addr>>16), byte(addr>>24))
	return []byte(ip.To4())
}

func appendString(dst []byte, s string) []byte {
	if len(s) > 65535 {
		s = s[:65535]
	}
	dst = appendUint16(dst, uint16(len(s)))
	return append(dst, []byte(s)...)
}

func appendUint16(dst []byte, v uint16) []byte {
	var b [2]byte
	binary.LittleEndian.PutUint16(b[:], v)
	return append(dst, b[:]...)
}

func appendUint32(dst []byte, v uint32) []byte {
	var b [4]byte
	binary.LittleEndian.PutUint32(b[:], v)
	return append(dst, b[:]...)
}

func appendInt32(dst []byte, v int32) []byte {
	return appendUint32(dst, uint32(v))
}

func appendUint64(dst []byte, v uint64) []byte {
	var b [8]byte
	binary.LittleEndian.PutUint64(b[:], v)
	return append(dst, b[:]...)
}

func (d *EBPFDriver) openReaders() error {
	readerMaps := []string{"events", "file_events", "net_events", "sec_events", "lsm_events"}
	for _, name := range readerMaps {
		m, ok := d.coll.Maps[name]
		if !ok {
			continue
		}
		r, err := ringbuf.NewReader(m)
		if err != nil {
			return fmt.Errorf("opening ring buffer %s: %w", name, err)
		}
		d.readers = append(d.readers, r)
	}
	if len(d.readers) == 0 {
		return fmt.Errorf("no ring buffer maps found in ebpf collection")
	}
	d.reader = d.readers[0]
	return nil
}
