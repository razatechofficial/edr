//go:build linux

package collector

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/razatechofficial/edr/internal/config"
	"github.com/razatechofficial/edr/internal/kernel"
	"github.com/razatechofficial/edr/internal/schema"
	"github.com/razatechofficial/edr/internal/selfprotect"
	"github.com/razatechofficial/edr/internal/telemetryenrich"
)

const (
	rawHdrSize      = 26
	bpfEvtProcExec  = 1
	bpfEvtProcExit  = 2
	bpfEvtProcFork  = 3
	bpfEvtFileOpen  = 6
	bpfEvtFileWrite = 7
	bpfEvtFileDel   = 8
	bpfEvtFileRen   = 9
	bpfEvtFileChmod = 28
	bpfEvtNetConn   = 11
	bpfEvtNetAccept = 12
	bpfEvtNetBind   = 13
	bpfEvtNetClose  = 14
	bpfEvtModule    = 22
	bpfEvtDNSQuery  = 35
)

// KernelCollector wraps the eBPF kernel driver and presents its real-time
// events through the Collector interface. Events are buffered between Collect
// calls so the tick-based agent loop can drain them.
type KernelCollector struct {
	driver     *kernel.EBPFDriver
	buf        *kernel.RingBuffer
	endpointID string
	hostname   string
	cfg        config.Config
	users      *UsernameCache
	fileDedupe *LinuxFileDeduper
	lineage    *LineageTracker

	mu     sync.Mutex
	events []Telemetry
	cancel context.CancelFunc
}

// AttachLinuxFileDedupe wires the shared Linux file-event deduper for health stats (optional).
func (kc *KernelCollector) AttachLinuxFileDedupe(d *LinuxFileDeduper) {
	if kc == nil {
		return
	}
	kc.fileDedupe = d
}

// AttachLineageTracker enriches eBPF file events with process image/comm from the shared tracker.
func (kc *KernelCollector) AttachLineageTracker(t *LineageTracker) {
	if kc == nil {
		return
	}
	kc.lineage = t
}

func (kc *KernelCollector) enrichFileLineage(fe *schema.FileEvent) {
	if kc == nil || kc.lineage == nil || fe == nil || fe.ActorPID <= 0 {
		return
	}
	e, ok := kc.lineage.Get(uint32(fe.ActorPID))
	if !ok {
		return
	}
	if fe.ActorExe == "" && e.ImagePath != "" {
		fe.ActorExe = e.ImagePath
	}
	if fe.ActorComm == "" && e.Comm != "" {
		fe.ActorComm = e.Comm
	}
	if fe.ActorPPID == 0 && e.ParentPID != 0 {
		fe.ActorPPID = int(e.ParentPID)
	}
}

// NewKernelCollector creates a collector backed by the Linux eBPF driver.
// Returns nil if running as non-root or if driver init fails.
func NewKernelCollector(endpointID string, cfg config.Config, users *UsernameCache) *KernelCollector {
	if os.Getuid() != 0 {
		return nil
	}
	driver, err := kernel.NewEBPFDriver(endpointID, cfg.Monitoring.BPFObjectPath)
	if err != nil {
		return nil
	}
	hostname, _ := os.Hostname()
	return &KernelCollector{
		driver:     driver,
		buf:        kernel.NewRingBuffer(65536),
		endpointID: endpointID,
		hostname:   hostname,
		cfg:        cfg,
		users:      users,
	}
}

// ExportMonitoringHealth implements ExportMonitoringHealth for monitoring doctor snapshots.
func (kc *KernelCollector) ExportMonitoringHealth() map[string]any {
	if kc == nil || kc.driver == nil || kc.buf == nil {
		return nil
	}
	extras := map[string]any{
		"bpf_pin_path_requested": strings.TrimSpace(kc.cfg.Monitoring.LinuxBPFPinPath),
	}
	if ld := kc.driver.LastLoadDiagnostics(); ld != "" {
		extras["bpf_load_diag"] = ld
	}
	if kc.fileDedupe != nil {
		if sm := kc.fileDedupe.StatsMap(); sm != nil {
			for k, v := range sm {
				extras["file_dedupe_"+k] = v
			}
		}
	}
	rs := kc.buf.Stats()
	extras["ring_bytes_used"] = rs.BytesUsed
	extras["ring_capacity_bytes"] = rs.Capacity
	extras["ring_backlog_pct"] = rs.BacklogPct
	tamperSignals := map[string]any{}
	for k, v := range kc.driver.TamperMetrics() {
		extras[k] = v
		tamperSignals[k] = v
	}
	extras = MergeTamperHealth(extras, "linux_kernel_monitoring", selfprotect.AntiDebugPosture(), tamperSignals)
	return KernelHealthMap("ebpf", kc.driver.Stats(), kc.buf.Stats(), extras)
}

func (kc *KernelCollector) Name() string { return "kernel" }

// Start launches the eBPF driver and begins reading events from the ring
// buffer into the internal queue.
func (kc *KernelCollector) Start(ctx context.Context) error {
	ctx, kc.cancel = context.WithCancel(ctx)
	kc.driver.SetBPFPinPath(kc.cfg.Monitoring.LinuxBPFPinPath)
	if err := kc.driver.Start(ctx, kc.buf); err != nil {
		return err
	}
	go kc.readLoop(ctx)
	return nil
}

// Collect drains buffered kernel events.
func (kc *KernelCollector) Collect(_ context.Context) ([]Telemetry, error) {
	kc.mu.Lock()
	batch := kc.events
	kc.events = nil
	kc.mu.Unlock()
	return batch, nil
}

func (kc *KernelCollector) Stop() {
	if kc.cancel != nil {
		kc.cancel()
	}
	kc.driver.Stop()
}

func (kc *KernelCollector) readLoop(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		data, err := kc.buf.TryRead()
		if err != nil || data == nil {
			time.Sleep(time.Millisecond)
			continue
		}

		tel := kc.parseEvent(data)
		if tel != nil {
			kc.maybeEnrichProcessImageHash(tel)
			kc.mu.Lock()
			kc.events = append(kc.events, *tel)
			kc.mu.Unlock()
		}
	}
}

func (kc *KernelCollector) parseEvent(data []byte) *Telemetry {
	if len(data) >= rawHdrSize {
		if tel := kc.parseBinaryEvent(data); tel != nil {
			return tel
		}
	}
	tel := MapKernelJSONToTelemetry(data, kc.endpointID, kc.hostname, runtime.GOOS, kc.users)
	if tel != nil && tel.File != nil {
		kc.enrichFileLineage(tel.File)
	}
	return tel
}

func (kc *KernelCollector) parseBinaryEvent(data []byte) *Telemetry {
	typ := binary.LittleEndian.Uint16(data[0:2])
	pid := binary.LittleEndian.Uint32(data[10:14])

	now := time.Now().UTC()
	base := schema.BaseEvent{
		SchemaVersion: schema.SchemaVersionV1,
		EndpointID:    kc.endpointID,
		Timestamp:     now,
		Hostname:      kc.hostname,
		OS:            runtime.GOOS,
	}
	payload := data[rawHdrSize:]

	switch typ {
	case bpfEvtProcExec, bpfEvtProcExit, bpfEvtProcFork:
		switch typ {
		case bpfEvtProcFork:
			base.EventType = schema.EventFork
			fk := &schema.ForkEvent{BaseEvent: base, ParentPID: int(pid)}
			if len(payload) >= 12 {
				fk.ChildPID = int(binary.LittleEndian.Uint32(payload[0:4]))
				fk.CloneFlags = binary.LittleEndian.Uint64(payload[4:12])
			}
			if fk.CloneFlags&0x100 != 0 {
				fk.IsThread = true
			}
			const cloneNsMask = uint64(0x20000 | 0x2000000 | 0x4000000 | 0x8000000 | 0x10000000 | 0x20000000 | 0x40000000)
			fk.IsContainer = fk.CloneFlags&cloneNsMask != 0
			return &Telemetry{Fork: fk}
		}
		base.EventType = schema.EventProcess
		pe := &schema.ProcessEvent{BaseEvent: base, PID: int(pid)}
		switch typ {
		case bpfEvtProcExec:
			ppid, rest := readUint32(payload)
			pe.PPID = int(ppid)
			filename, rest := readLenStr(rest)
			pe.ProcessPath = filename
			cmdLine, rest := readLenStr(rest)
			pe.CommandLine = cmdLine
			_, rest = readLenStr(rest) // skip
			comm, _ := readLenStr(rest)
			pe.ProcessName = comm
		case bpfEvtProcExit:
			pe.ProcessName = "exit"
		}
		if kc.users != nil {
			uid := binary.LittleEndian.Uint32(data[18:22])
			pe.User = kc.users.Lookup(strconv.FormatUint(uint64(uid), 10))
		}
		return &Telemetry{Process: pe}

	case bpfEvtFileOpen, bpfEvtFileWrite, bpfEvtFileDel, bpfEvtFileRen, bpfEvtFileChmod:
		base.EventType = schema.EventFile
		fe := &schema.FileEvent{BaseEvent: base, ActorPID: int(pid)}
		switch typ {
		case bpfEvtFileOpen:
			fe.Operation = "open"
			fname, rest := readLenStr(payload)
			fe.Path = fname
			if len(rest) >= 4 {
				fe.OpenFlags = binary.LittleEndian.Uint32(rest[:4])
			}
		case bpfEvtFileWrite:
			fe.Operation = "write"
			fname, rest := readLenStr(payload)
			fe.Path = fname
			if len(rest) >= 8 {
				fe.BytesWritten = binary.LittleEndian.Uint64(rest[:8])
				rest = rest[8:]
			}
			if len(rest) >= 4 {
				fe.WriteFD = int(binary.LittleEndian.Uint32(rest[:4]))
			}
		case bpfEvtFileDel:
			fe.Operation = "delete"
			if fname, _ := readLenStr(payload); fname != "" {
				fe.Path = fname
			}
		case bpfEvtFileRen:
			fe.Operation = "rename"
			oldp, rest := readLenStr(payload)
			newp, _ := readLenStr(rest)
			switch {
			case oldp != "" && newp != "":
				fe.Path = oldp + " -> " + newp
			case oldp != "":
				fe.Path = oldp
			default:
				fe.Path = newp
			}
		case bpfEvtFileChmod:
			fe.Operation = "chmod"
			fname, rest := readLenStr(payload)
			fe.Path = fname
			if len(rest) >= 4 {
				fe.ChmodMode = binary.LittleEndian.Uint32(rest[:4])
				rest = rest[4:]
			}
			if len(rest) >= 4 {
				fe.FchmodatFlags = binary.LittleEndian.Uint32(rest[:4])
			}
			fe.SUID = fe.ChmodMode&04000 != 0
		}
		kc.enrichFileLineage(fe)
		return &Telemetry{File: fe}

	case bpfEvtModule:
		base.EventType = schema.EventProcess
		moduleName, _ := readLenStr(payload)
		pe := &schema.ProcessEvent{
			BaseEvent:   base,
			PID:         int(pid),
			ProcessName: "kernel_module_load",
			ProcessPath: moduleName,
			CommandLine: "init_module:" + moduleName,
		}
		return &Telemetry{Process: pe}

	case bpfEvtNetConn, bpfEvtNetAccept, bpfEvtNetBind, bpfEvtNetClose, bpfEvtDNSQuery:
		base.EventType = schema.EventNetwork
		ne := &schema.NetworkEvent{BaseEvent: base, PID: int(pid)}
		// Encode the operation in Protocol so downstream rules and the lineage
		// correlator can distinguish connect/accept/bind/close without an extra
		// schema field. Format: "<proto>:<op>".
		opSuffix := ""
		switch typ {
		case bpfEvtNetConn:
			opSuffix = "connect"
		case bpfEvtNetAccept:
			opSuffix = "accept"
		case bpfEvtNetBind:
			opSuffix = "bind"
		case bpfEvtNetClose:
			opSuffix = "close"
		case bpfEvtDNSQuery:
			opSuffix = "dns_query"
		}
		if len(payload) < 3 {
			ne.Protocol = opSuffix
			return &Telemetry{Network: ne}
		}
		family := payload[0]
		proto := payload[1]
		rest := payload[3:]

		switch proto {
		case 6:
			ne.Protocol = "tcp"
		case 17:
			ne.Protocol = "udp"
		default:
			ne.Protocol = fmt.Sprintf("proto_%d", proto)
		}
		if opSuffix != "" {
			ne.Protocol = ne.Protocol + ":" + opSuffix
		}

		if family == 10 { // IPv6
			if len(rest) >= 36 {
				ne.SourceIP = net.IP(rest[:16]).String()
				ne.SourcePt = int(binary.LittleEndian.Uint16(rest[16:18]))
				ne.DestIP = net.IP(rest[18:34]).String()
				ne.DestPt = int(binary.LittleEndian.Uint16(rest[34:36]))
			}
		} else { // IPv4
			if len(rest) >= 12 {
				ne.SourceIP = net.IP(rest[:4]).String()
				ne.SourcePt = int(binary.LittleEndian.Uint16(rest[4:6]))
				ne.DestIP = net.IP(rest[6:10]).String()
				ne.DestPt = int(binary.LittleEndian.Uint16(rest[10:12]))
			}
		}
		return &Telemetry{Network: ne}
	}

	return nil
}

const maxExecImageHashBytes = 32 << 20

func (kc *KernelCollector) maybeEnrichProcessImageHash(tel *Telemetry) {
	if !kc.cfg.Monitoring.EnrichExecImageSHA256 || tel == nil || tel.Process == nil {
		return
	}
	p := tel.Process.ProcessPath
	if p == "" {
		return
	}
	if h := telemetryenrich.FileSHA256Hex(p, maxExecImageHashBytes); h != "" {
		tel.Process.ImageSHA256 = h
	}
}

func readUint32(data []byte) (uint32, []byte) {
	if len(data) < 4 {
		return 0, nil
	}
	return binary.LittleEndian.Uint32(data[:4]), data[4:]
}

func readLenStr(data []byte) (string, []byte) {
	if len(data) < 2 {
		return "", nil
	}
	n := int(binary.LittleEndian.Uint16(data[:2]))
	data = data[2:]
	if len(data) < n {
		return string(data), nil
	}
	return string(data[:n]), data[n:]
}
