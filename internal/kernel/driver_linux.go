//go:build linux

package kernel

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"os"
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
	bpfCommLen     = 16
	bpfFilenameLen = 256
	bpfArgsLen     = 512
	bpfObjectPath  = "/var/lib/edr/bpf/edr.bpf.o"

	bpfEvtProcess uint32 = 0
	bpfEvtFile    uint32 = 1
	bpfEvtNetwork uint32 = 2
)

// Placeholder for compiled eBPF bytecode. Uncomment after running `make bpf`:
// //go:embed bpf/edr.bpf.o
// var bpfBytecode []byte

// bpfProcessEvent mirrors the C struct process_event emitted by the eBPF program.
type bpfProcessEvent struct {
	PID      uint32
	PPID     uint32
	UID      uint32
	GID      uint32
	Comm     [bpfCommLen]byte
	Filename [bpfFilenameLen]byte
	ArgsSize uint32
	Args     [bpfArgsLen]byte
}

// bpfFileEvent mirrors the C struct file_event emitted by the eBPF program.
type bpfFileEvent struct {
	PID       uint32
	UID       uint32
	EventType uint32
	Filename  [bpfFilenameLen]byte
	Flags     uint32
	Mode      uint32
}

// bpfNetworkEvent mirrors the C struct network_event emitted by the eBPF program.
type bpfNetworkEvent struct {
	PID      uint32
	UID      uint32
	SrcAddr  uint32
	DstAddr  uint32
	SrcPort  uint16
	DstPort  uint16
	Protocol uint8
	Family   uint8
	_        [2]byte
}

// EBPFDriver implements Driver using eBPF tracepoints and ring buffers on Linux.
type EBPFDriver struct {
	agentID   string
	mu        sync.RWMutex
	policy    EventPolicy
	startTime time.Time

	coll   *ebpf.Collection
	links  []link.Link
	reader *ringbuf.Reader

	cancel  context.CancelFunc
	wg      sync.WaitGroup
	running atomic.Bool
	buf     *RingBuffer

	received  atomic.Uint64
	dropped   atomic.Uint64
	processed atomic.Uint64
	errors    atomic.Uint64
}

// NewEBPFDriver creates a new eBPF-based kernel driver. Requires root privileges.
func NewEBPFDriver(agentID string) (*EBPFDriver, error) {
	if os.Getuid() != 0 {
		return nil, fmt.Errorf("ebpf driver requires root privileges")
	}
	return &EBPFDriver{
		agentID: agentID,
		policy:  DefaultPolicy(),
	}, nil
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
	}
}

// Start loads eBPF programs, attaches tracepoints, and begins event collection.
func (d *EBPFDriver) Start(ctx context.Context, buf *RingBuffer) error {
	if d.running.Load() {
		return fmt.Errorf("ebpf driver already running")
	}

	d.buf = buf

	var child context.Context
	child, d.cancel = context.WithCancel(ctx)

	spec, err := d.loadCollection()
	if err != nil {
		return fmt.Errorf("loading ebpf collection: %w", err)
	}

	coll, err := ebpf.NewCollectionWithOptions(spec, ebpf.CollectionOptions{})
	if err != nil {
		return fmt.Errorf("creating ebpf collection: %w", err)
	}
	d.coll = coll

	if err := d.attachTracepoints(); err != nil {
		d.cleanup()
		return fmt.Errorf("attaching tracepoints: %w", err)
	}

	eventsMap, ok := d.coll.Maps["events"]
	if !ok {
		d.cleanup()
		return fmt.Errorf("events ring buffer map not found in ebpf collection")
	}

	reader, err := ringbuf.NewReader(eventsMap)
	if err != nil {
		d.cleanup()
		return fmt.Errorf("opening ebpf ring buffer reader: %w", err)
	}
	d.reader = reader

	if err := d.syncPolicyToMaps(); err != nil {
		d.cleanup()
		return fmt.Errorf("syncing initial policy: %w", err)
	}

	d.startTime = time.Now()
	d.running.Store(true)

	d.wg.Add(1)
	go d.eventLoop(child)

	return nil
}

// Stop detaches all eBPF hooks, closes the reader, and releases resources.
func (d *EBPFDriver) Stop() error {
	if !d.running.CompareAndSwap(true, false) {
		return nil
	}
	d.cancel()
	if d.reader != nil {
		d.reader.Close()
	}
	d.wg.Wait()
	d.cleanup()
	return nil
}

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
	if d.coll != nil {
		d.coll.Close()
		d.coll = nil
	}
}

func (d *EBPFDriver) loadCollection() (*ebpf.CollectionSpec, error) {
	// When compiled with go:embed, use the embedded bytecode:
	// if len(bpfBytecode) > 0 {
	//     return ebpf.LoadCollectionSpecFromReader(bytes.NewReader(bpfBytecode))
	// }
	if _, err := os.Stat(bpfObjectPath); err != nil {
		return nil, fmt.Errorf(
			"ebpf object not found at %s (compile with 'make bpf'): %w",
			bpfObjectPath, err,
		)
	}
	return ebpf.LoadCollectionSpec(bpfObjectPath)
}

func (d *EBPFDriver) attachTracepoints() error {
	type tp struct {
		group, name, prog string
	}
	tracepoints := []tp{
		{"sched", "sched_process_exec", "tp_sched_process_exec"},
		{"sched", "sched_process_exit", "tp_sched_process_exit"},
		{"sched", "sched_process_fork", "tp_sched_process_fork"},
		{"syscalls", "sys_enter_openat", "tp_sys_enter_openat"},
		{"syscalls", "sys_enter_write", "tp_sys_enter_write"},
		{"syscalls", "sys_enter_connect", "tp_sys_enter_connect"},
		{"syscalls", "sys_enter_accept4", "tp_sys_enter_accept4"},
	}

	for _, t := range tracepoints {
		prog, ok := d.coll.Programs[t.prog]
		if !ok {
			continue
		}
		l, err := link.Tracepoint(t.group, t.name, prog, nil)
		if err != nil {
			return fmt.Errorf("attaching %s/%s: %w", t.group, t.name, err)
		}
		d.links = append(d.links, l)
	}
	if len(d.links) == 0 {
		return fmt.Errorf("no tracepoints attached; verify ebpf programs are present")
	}
	return nil
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

func (d *EBPFDriver) eventLoop(ctx context.Context) {
	defer d.wg.Done()
	for {
		record, err := d.reader.Read()
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
	payload := raw[4:]

	d.mu.RLock()
	p := d.policy
	d.mu.RUnlock()

	switch typ {
	case bpfEvtProcess:
		if !p.ProcessEvents {
			return nil
		}
		return d.decodeProcessEvent(payload)
	case bpfEvtFile:
		if !p.FileEvents {
			return nil
		}
		return d.decodeFileEvent(payload)
	case bpfEvtNetwork:
		if !p.NetworkEvents {
			return nil
		}
		return d.decodeNetworkEvent(payload)
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
	return d.writeEvent(map[string]interface{}{
		"type":      events.EventProcess,
		"timestamp": time.Now().UTC(),
		"agent_id":  d.agentID,
		"pid":       evt.PID,
		"ppid":      evt.PPID,
		"uid":       evt.UID,
		"gid":       evt.GID,
		"comm":      nullTerminated(evt.Comm[:]),
		"filename":  nullTerminated(evt.Filename[:]),
		"args":      nullTerminated(evt.Args[:min(int(evt.ArgsSize), bpfArgsLen)]),
	})
}

func (d *EBPFDriver) decodeFileEvent(data []byte) error {
	const sz = unsafe.Sizeof(bpfFileEvent{})
	if uintptr(len(data)) < sz {
		return fmt.Errorf("file event truncated: got %d, want %d", len(data), sz)
	}

	evt := (*bpfFileEvent)(unsafe.Pointer(&data[0]))
	return d.writeEvent(map[string]interface{}{
		"type":      events.EventFile,
		"timestamp": time.Now().UTC(),
		"agent_id":  d.agentID,
		"pid":       evt.PID,
		"uid":       evt.UID,
		"sub_type":  evt.EventType,
		"filename":  nullTerminated(evt.Filename[:]),
		"flags":     evt.Flags,
		"mode":      evt.Mode,
	})
}

func (d *EBPFDriver) decodeNetworkEvent(data []byte) error {
	const sz = unsafe.Sizeof(bpfNetworkEvent{})
	if uintptr(len(data)) < sz {
		return fmt.Errorf("network event truncated: got %d, want %d", len(data), sz)
	}

	evt := (*bpfNetworkEvent)(unsafe.Pointer(&data[0]))
	return d.writeEvent(map[string]interface{}{
		"type":      events.EventNetwork,
		"timestamp": time.Now().UTC(),
		"agent_id":  d.agentID,
		"pid":       evt.PID,
		"uid":       evt.UID,
		"src_addr":  uint32ToIPv4(evt.SrcAddr),
		"dst_addr":  uint32ToIPv4(evt.DstAddr),
		"src_port":  evt.SrcPort,
		"dst_port":  evt.DstPort,
		"protocol":  evt.Protocol,
		"family":    evt.Family,
	})
}

func (d *EBPFDriver) writeEvent(envelope map[string]interface{}) error {
	data, err := json.Marshal(envelope)
	if err != nil {
		return fmt.Errorf("marshaling event: %w", err)
	}
	return d.buf.Write(data)
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
