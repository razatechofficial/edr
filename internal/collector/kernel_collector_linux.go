//go:build linux

package collector

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"runtime"
	"sync"
	"time"

	"github.com/razatechofficial/edr/internal/kernel"
	"github.com/razatechofficial/edr/internal/schema"
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
	bpfEvtNetConn   = 11
	bpfEvtNetAccept = 12
	bpfEvtNetBind   = 13
)

// KernelCollector wraps the eBPF kernel driver and presents its real-time
// events through the Collector interface. Events are buffered between Collect
// calls so the tick-based agent loop can drain them.
type KernelCollector struct {
	driver     *kernel.EBPFDriver
	buf        *kernel.RingBuffer
	endpointID string
	hostname   string

	mu     sync.Mutex
	events []Telemetry
	cancel context.CancelFunc
}

// NewKernelCollector creates a collector backed by the Linux eBPF driver.
// Returns nil if running as non-root or if driver init fails.
func NewKernelCollector(endpointID string) *KernelCollector {
	if os.Getuid() != 0 {
		return nil
	}
	driver, err := kernel.NewEBPFDriver(endpointID)
	if err != nil {
		return nil
	}
	hostname, _ := os.Hostname()
	return &KernelCollector{
		driver:     driver,
		buf:        kernel.NewRingBuffer(65536),
		endpointID: endpointID,
		hostname:   hostname,
	}
}

func (kc *KernelCollector) Name() string { return "kernel" }

// Start launches the eBPF driver and begins reading events from the ring
// buffer into the internal queue.
func (kc *KernelCollector) Start(ctx context.Context) error {
	ctx, kc.cancel = context.WithCancel(ctx)
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
	return MapKernelJSONToTelemetry(data, kc.endpointID, kc.hostname, runtime.GOOS)
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
		base.EventType = schema.EventProcess
		pe := &schema.ProcessEvent{BaseEvent: base, PID: int(pid)}
		if typ == bpfEvtProcExec {
			ppid, rest := readUint32(payload)
			pe.PPID = int(ppid)
			filename, rest := readLenStr(rest)
			pe.ProcessPath = filename
			cmdLine, rest := readLenStr(rest)
			pe.CommandLine = cmdLine
			_, rest = readLenStr(rest) // skip
			comm, _ := readLenStr(rest)
			pe.ProcessName = comm
		}
		return &Telemetry{Process: pe}

	case bpfEvtFileOpen, bpfEvtFileWrite, bpfEvtFileDel, bpfEvtFileRen:
		base.EventType = schema.EventFile
		fe := &schema.FileEvent{BaseEvent: base, ActorPID: int(pid)}
		switch typ {
		case bpfEvtFileOpen:
			fe.Operation = "open"
		case bpfEvtFileWrite:
			fe.Operation = "write"
		case bpfEvtFileDel:
			fe.Operation = "delete"
		case bpfEvtFileRen:
			fe.Operation = "rename"
		}
		if fname, _ := readLenStr(payload); fname != "" {
			fe.Path = fname
		}
		return &Telemetry{File: fe}

	case bpfEvtNetConn, bpfEvtNetAccept, bpfEvtNetBind:
		base.EventType = schema.EventNetwork
		ne := &schema.NetworkEvent{BaseEvent: base}
		if len(payload) < 3 {
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
