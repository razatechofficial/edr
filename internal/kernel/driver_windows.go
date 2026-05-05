//go:build windows

package kernel

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"runtime"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	"github.com/razatechofficial/edr/pkg/events"
	"golang.org/x/sys/windows"
)

const (
	eventTraceRealTimeMode               = 0x00000100
	wnodeFlagTracedGUID                  = 0x00020000
	eventControlCodeEnableProvider       = 1
	eventTraceControlStop                = 1
	traceLevelVerbose                    = 5
	processTraceModeRealTime             = 0x00000100
	processTraceModeEventRecord          = 0x10000000
	invalidProcesstraceHandle            = ^uint64(0)
	filetimeToUnixEpochDelta       int64 = 116444736000000000

	defaultETWIngestDepth = 4096
	maxETWUserDataCopy    = 64 * 1024
	// EVENT_TRACE_SECURE_MODE — prefer tamper-resistant realtime delivery where supported.
	eventTraceSecureMode = 0x80000000
)

var (
	kernelProcessGUID = windows.GUID{
		Data1: 0x22FB2CD6, Data2: 0x0E7B, Data3: 0x422B,
		Data4: [8]byte{0xA0, 0xC7, 0x2F, 0xAD, 0x1F, 0xD0, 0xE7, 0x16},
	}
	kernelFileGUID = windows.GUID{
		Data1: 0xEDD08927, Data2: 0x9CC4, Data3: 0x4E65,
		Data4: [8]byte{0xB9, 0x70, 0xC2, 0x56, 0x0F, 0xB5, 0xC2, 0x89},
	}
	kernelNetworkGUID = windows.GUID{
		Data1: 0x7DD42A49, Data2: 0x5329, Data3: 0x4832,
		Data4: [8]byte{0x8D, 0xFD, 0x43, 0xD9, 0x79, 0x15, 0x3A, 0x88},
	}
	dnsClientGUID = windows.GUID{
		Data1: 0x1C95126E, Data2: 0x7EEA, Data3: 0x49A9,
		Data4: [8]byte{0xA3, 0xFE, 0xA3, 0x78, 0xB0, 0x3D, 0xDB, 0x4D},
	}
	// Microsoft-Windows-Kernel-Registry: emits realtime registry create/open/
	// delete/setvalue events with PID + key path. Replaces the userland
	// registry polling on hosts that allow ETW autologger access.
	kernelRegistryGUID = windows.GUID{
		Data1: 0x70EB4F03, Data2: 0xC1DE, Data3: 0x4F73,
		Data4: [8]byte{0xA0, 0x51, 0x33, 0xD1, 0x3D, 0x54, 0x13, 0xBD},
	}
	wmiActivityGUID = windows.GUID{
		Data1: 0x141194EF, Data2: 0x0210, Data3: 0x4338,
		Data4: [8]byte{0xBC, 0xA5, 0x2B, 0xFF, 0x18, 0x28, 0x29, 0x30},
	}
	powershellGUID = windows.GUID{
		Data1: 0xA0C1853B, Data2: 0x5C3D, Data3: 0x4017,
		Data4: [8]byte{0xB7, 0x03, 0x33, 0x68, 0x9D, 0x46, 0x54, 0xC8},
	}
	kernelObjectGUID = windows.GUID{
		Data1: 0x47D920E5, Data2: 0x0CF2, Data3: 0x4746,
		Data4: [8]byte{0x94, 0x1D, 0x94, 0x16, 0x27, 0xD1, 0xFC, 0x01},
	}
	bitsClientGUID = windows.GUID{
		Data1: 0x2F07F7ED, Data2: 0x7968, Data3: 0x4BD6,
		Data4: [8]byte{0xBB, 0xD8, 0xB3, 0xE5, 0x02, 0x58, 0x46, 0xFF},
	}
	taskSchedulerGUID = windows.GUID{
		Data1: 0x48E5B3B2, Data2: 0xED82, Data3: 0x4617,
		Data4: [8]byte{0x8E, 0x1F, 0xA6, 0x37, 0xCA, 0x2B, 0x30, 0x91},
	}
)

var (
	advapi32           = windows.NewLazySystemDLL("advapi32.dll")
	procStartTrace     = advapi32.NewProc("StartTraceW")
	procControlTrace   = advapi32.NewProc("ControlTraceW")
	procEnableTraceEx2 = advapi32.NewProc("EnableTraceEx2")
	procOpenTrace      = advapi32.NewProc("OpenTraceW")
	procProcessTrace   = advapi32.NewProc("ProcessTrace")
	procCloseTrace     = advapi32.NewProc("CloseTrace")
)

// wnodeHeader mirrors the Windows WNODE_HEADER structure.
type wnodeHeader struct {
	BufferSize    uint32
	ProviderId    uint32
	HistoricalCtx uint64
	TimeStamp     int64
	GUID          windows.GUID
	ClientContext uint32
	Flags         uint32
}

// etwTraceProperties mirrors EVENT_TRACE_PROPERTIES including the WNODE_HEADER.
type etwTraceProperties struct {
	Wnode               wnodeHeader
	BufferSize          uint32
	MinimumBuffers      uint32
	MaximumBuffers      uint32
	MaximumFileSize     uint32
	LogFileMode         uint32
	FlushTimer          uint32
	EnableFlags         uint32
	AgeLimit            int32
	NumberOfBuffers     uint32
	FreeBuffers         uint32
	EventsLost          uint32
	BuffersWritten      uint32
	LogBuffersLost      uint32
	RealTimeBuffersLost uint32
	LoggerThread        uintptr
	LogFileNameOffset   uint32
	LoggerNameOffset    uint32
}

type etwEventDescriptor struct {
	Id      uint16
	Version uint8
	Channel uint8
	Level   uint8
	Opcode  uint8
	Task    uint16
	Keyword uint64
}

type etwEventHeader struct {
	Size            uint16
	HeaderType      uint16
	Flags           uint16
	EventProperty   uint16
	ThreadId        uint32
	ProcessId       uint32
	TimeStamp       int64
	ProviderId      windows.GUID
	EventDescriptor etwEventDescriptor
	ProcessorTime   uint64
	ActivityId      windows.GUID
}

type etwBufferContext struct {
	Union    uint16
	LoggerId uint16
}

// etwEventRecord mirrors the Windows EVENT_RECORD structure.
type etwEventRecord struct {
	EventHeader       etwEventHeader
	BufferContext     etwBufferContext
	ExtendedDataCount uint16
	UserDataLength    uint16
	ExtendedData      uintptr
	UserData          uintptr
	UserContext       uintptr
}

// etwRecordCopy is a bounded copy of EVENT_RECORD safe to decode off the ETW callback thread.
type etwRecordCopy struct {
	EventHeader   etwEventHeader
	BufferContext etwBufferContext
	UserData      []byte
}

type etwSystemTime struct {
	Year, Month, DayOfWeek, Day        uint16
	Hour, Minute, Second, Milliseconds uint16
}

type etwTimeZoneInfo struct {
	Bias         int32
	StandardName [32]uint16
	StandardDate etwSystemTime
	StandardBias int32
	DaylightName [32]uint16
	DaylightDate etwSystemTime
	DaylightBias int32
}

type etwEventTraceHeader struct {
	Size           uint16
	FieldTypeFlags uint16
	Version        uint32
	ThreadId       uint32
	ProcessId      uint32
	TimeStamp      int64
	GUID           windows.GUID
	ProcessorTime  uint64
}

type etwEventTrace struct {
	Header           etwEventTraceHeader
	InstanceId       uint32
	ParentInstanceId uint32
	ParentGuid       windows.GUID
	MofData          uintptr
	MofLength        uint32
	BufferContext    uint32
}

type etwTraceLogfileHeader struct {
	BufferSize         uint32
	Version            uint32
	ProviderVersion    uint32
	NumberOfProcessors uint32
	EndTime            int64
	TimerResolution    uint32
	MaximumFileSize    uint32
	LogFileMode        uint32
	BuffersWritten     uint32
	LogInstanceGuid    windows.GUID
	LoggerName         uintptr
	LogFileName        uintptr
	TimeZone           etwTimeZoneInfo
	BootTime           int64
	PerfFreq           int64
	StartTime          int64
	ReservedFlags      uint32
	BuffersLost        uint32
}

// etwEventTraceLogfile mirrors EVENT_TRACE_LOGFILEW on x64.
type etwEventTraceLogfile struct {
	LogFileName      uintptr
	LoggerName       uintptr
	CurrentTime      int64
	BuffersRead      uint32
	ProcessTraceMode uint32
	CurrentEvent     etwEventTrace
	LogfileHeader    etwTraceLogfileHeader
	BufferCallback   uintptr
	BufferSize       uint32
	Filled           uint32
	EventsLost       uint32
	_pad1            uint32
	EventRecordCb    uintptr
	IsKernelTrace    uint32
	_pad2            uint32
	Context          uintptr
}

type providerConfig struct {
	name      string
	guid      windows.GUID
	eventType events.EventType
}

var etwCoreProviders = []providerConfig{
	{"Process", kernelProcessGUID, events.EventProcess},
	{"File", kernelFileGUID, events.EventFile},
	{"Network", kernelNetworkGUID, events.EventNetwork},
	{"DNS", dnsClientGUID, events.EventDNS},
	{"Registry", kernelRegistryGUID, events.EventRegistry},
}

func (d *ETWDriver) providersToStart() []providerConfig {
	d.mu.RLock()
	p := d.policy
	d.mu.RUnlock()

	var out []providerConfig
	for _, pc := range etwCoreProviders {
		if d.policyAllows(pc.eventType) {
			out = append(out, pc)
		}
	}
	if p.ETWWMIActivity {
		out = append(out, providerConfig{"WMI", wmiActivityGUID, events.EventWMI})
	}
	if p.ETWPowerShellScript {
		out = append(out, providerConfig{"PowerShell", powershellGUID, events.EventPowerShell})
	}
	if p.ETWNamedPipeHandles {
		out = append(out, providerConfig{"KernelObject", kernelObjectGUID, events.EventPipe})
	}
	if p.ETWBitsClient {
		out = append(out, providerConfig{"BitsClient", bitsClientGUID, events.EventBITS})
	}
	if p.ETWTaskScheduler {
		out = append(out, providerConfig{"TaskScheduler", taskSchedulerGUID, events.EventTask})
	}
	return out
}

func isOptionalETWProvider(name string) bool {
	switch name {
	case "WMI", "PowerShell", "KernelObject", "BitsClient", "TaskScheduler":
		return true
	default:
		return false
	}
}

type etwSession struct {
	name          string
	nameUTF16     *uint16
	provider      windows.GUID
	providerName  string
	sessionHandle uint64
	traceHandle   uint64
	active        atomic.Bool
	wg            sync.WaitGroup

	recoveryAttempted atomic.Bool
}

// ETWDriver implements Driver using Event Tracing for Windows.
type ETWDriver struct {
	agentID   string
	mu        sync.RWMutex
	policy    EventPolicy
	startTime time.Time
	running   atomic.Bool
	buf       *RingBuffer
	cancel    context.CancelFunc
	sessions  []*etwSession

	received  atomic.Uint64
	dropped   atomic.Uint64
	processed atomic.Uint64
	errors    atomic.Uint64

	tiCap tiCapability

	provMu     sync.RWMutex
	provHealth []ETWProviderHealth

	fileObjMu   sync.RWMutex
	fileObjPath map[uint64]string
	fileObjFIFO []uint64
	fileObjCap  int

	// Callback → worker handoff (non-blocking enqueue).
	ingestCh      chan etwRecordCopy
	ingestWg      sync.WaitGroup
	ingestDropped atomic.Uint64

	secureTrace atomic.Bool

	sessionRecoverAttempts atomic.Uint64
}

// globalETW holds the active ETWDriver for the event record callback.
var globalETW atomic.Pointer[ETWDriver]

var etwCallbackPtr = windows.NewCallback(etwEventRecordCallback)

// NewETWDriver creates a new ETW-based kernel driver for Windows.
func NewETWDriver(agentID string) (*ETWDriver, error) {
	return &ETWDriver{
		agentID:     agentID,
		policy:      DefaultPolicy(),
		fileObjPath: make(map[uint64]string),
		fileObjCap:  65536,
	}, nil
}

// Name returns the driver identifier.
func (d *ETWDriver) Name() string { return "etw" }

// Capabilities reports which event types this driver can collect.
func (d *ETWDriver) Capabilities() []events.EventType {
	return []events.EventType{
		events.EventProcess,
		events.EventFile,
		events.EventNetwork,
		events.EventDNS,
		events.EventRegistry,
		events.EventWMI,
		events.EventPowerShell,
		events.EventPipe,
		events.EventBITS,
		events.EventTask,
	}
}

// Start creates ETW trace sessions for each configured provider and begins event collection.
func (d *ETWDriver) Start(ctx context.Context, buf *RingBuffer) error {
	if d.running.Load() {
		return fmt.Errorf("etw driver already running")
	}

	d.buf = buf
	childCtx, cancel := context.WithCancel(ctx)
	d.cancel = cancel

	d.ingestCh = make(chan etwRecordCopy, defaultETWIngestDepth)
	d.ingestWg.Add(1)
	go d.ingestLoop(childCtx)

	if !globalETW.CompareAndSwap(nil, d) {
		cancel()
		d.ingestWg.Wait()
		d.ingestCh = nil
		return fmt.Errorf("another etw driver instance is already active")
	}

	startOK := false
	defer func() {
		if startOK {
			return
		}
		globalETW.Store(nil)
		cancel()
		d.stopAllSessions()
		d.sessions = nil
		d.ingestWg.Wait()
		d.ingestCh = nil
	}()

	d.provMu.Lock()
	d.provHealth = nil
	d.provMu.Unlock()

	for _, p := range d.providersToStart() {
		optional := isOptionalETWProvider(p.name)
		sess, err := d.createSession(p.name, p.guid)
		if err != nil {
			if optional {
				d.recordProviderHealth(p.name, false, err.Error())
				continue
			}
			return fmt.Errorf("creating %s session: %w", p.name, err)
		}
		if err := d.openAndProcess(sess); err != nil {
			d.stopLoggerOnly(sess)
			if optional {
				d.recordProviderHealth(p.name, false, err.Error())
				continue
			}
			return fmt.Errorf("opening %s trace: %w", p.name, err)
		}
		d.sessions = append(d.sessions, sess)
		d.recordProviderHealth(p.name, true, "")
	}

	if len(d.sessions) == 0 {
		return fmt.Errorf("no ETW sessions were started (check policy)")
	}

	d.startTime = time.Now()
	d.running.Store(true)
	startOK = true

	d.mu.RLock()
	wantTI := d.policy.ETWThreatIntel
	d.mu.RUnlock()
	if !wantTI {
		d.tiCap.skipThreatIntelProbe("monitoring.etw_threat_intel=false")
		d.emitTIStatusEvent()
	} else {
		_ = d.probeThreatIntelProviders()
	}
	return nil
}

// Stop terminates all ETW trace sessions and releases resources.
func (d *ETWDriver) Stop() error {
	if !d.running.CompareAndSwap(true, false) {
		return nil
	}
	globalETW.Store(nil)
	if d.cancel != nil {
		d.cancel()
	}
	d.stopAllSessions()
	d.ingestWg.Wait()
	d.sessions = nil
	d.ingestCh = nil
	return nil
}

// SetPolicy updates the event collection policy.
func (d *ETWDriver) SetPolicy(policy EventPolicy) error {
	d.mu.Lock()
	d.policy = policy
	d.mu.Unlock()
	return nil
}

// Stats returns current driver metrics.
func (d *ETWDriver) Stats() DriverStats {
	var uptime float64
	if !d.startTime.IsZero() {
		uptime = time.Since(d.startTime).Seconds()
	}
	mode := ""
	if d.secureTrace.Load() {
		mode = "secure_etw"
	} else if !d.startTime.IsZero() {
		mode = "standard_etw"
	}
	return DriverStats{
		EventsReceived:  d.received.Load(),
		EventsDropped:   d.dropped.Load(),
		EventsProcessed: d.processed.Load(),
		UptimeSeconds:   uptime,
		ErrorCount:      d.errors.Load(),
		CollectionMode:  mode,
	}
}

// TamperMetrics reports ETW lifecycle anomalies relevant to anti-tamper monitoring.
func (d *ETWDriver) TamperMetrics() map[string]any {
	if d == nil {
		return nil
	}
	return map[string]any{
		"etw_session_recover_attempts": d.sessionRecoverAttempts.Load(),
	}
}

// IngestMetrics exposes ETW callback-queue telemetry for monitoring_health.json.
func (d *ETWDriver) IngestMetrics() map[string]any {
	if d == nil || d.ingestCh == nil {
		return nil
	}
	return map[string]any{
		"ingest_queue_depth": len(d.ingestCh),
		"ingest_queue_cap":   cap(d.ingestCh),
		"ingest_dropped":     d.ingestDropped.Load(),
	}
}

func (d *ETWDriver) recordProviderHealth(name string, active bool, errStr string) {
	d.provMu.Lock()
	defer d.provMu.Unlock()
	d.provHealth = append(d.provHealth, ETWProviderHealth{Name: name, Active: active, Error: errStr})
}

// ProviderHealthSnapshot returns the last ETW session outcomes (per provider).
func (d *ETWDriver) ProviderHealthSnapshot() []ETWProviderHealth {
	d.provMu.RLock()
	defer d.provMu.RUnlock()
	out := make([]ETWProviderHealth, len(d.provHealth))
	copy(out, d.provHealth)
	return out
}

// stopLoggerOnly stops a real-time logger without a consumer trace (OpenTrace failed).
func (d *ETWDriver) stopLoggerOnly(s *etwSession) {
	if s == nil || s.sessionHandle == 0 {
		return
	}
	propSize := unsafe.Sizeof(etwTraceProperties{})
	bufSize := propSize + 256*2
	buf := make([]byte, bufSize)
	props := (*etwTraceProperties)(unsafe.Pointer(&buf[0]))
	props.Wnode.BufferSize = uint32(bufSize)
	props.LoggerNameOffset = uint32(propSize)
	procControlTrace.Call(
		uintptr(s.sessionHandle),
		0,
		uintptr(unsafe.Pointer(props)),
		eventTraceControlStop,
	)
}

func (d *ETWDriver) policyAllows(et events.EventType) bool {
	d.mu.RLock()
	defer d.mu.RUnlock()
	switch et {
	case events.EventProcess:
		return d.policy.ProcessEvents
	case events.EventFile:
		return d.policy.FileEvents
	case events.EventNetwork:
		return d.policy.NetworkEvents
	case events.EventDNS:
		return d.policy.DNSEvents
	case events.EventRegistry:
		return d.policy.RegistryEvents
	case events.EventWMI:
		return d.policy.ETWWMIActivity
	case events.EventPowerShell:
		return d.policy.ETWPowerShellScript
	case events.EventPipe:
		return d.policy.ETWNamedPipeHandles
	case events.EventBITS:
		return d.policy.ETWBitsClient
	case events.EventTask:
		return d.policy.ETWTaskScheduler
	default:
		return true
	}
}

func (d *ETWDriver) createSession(name string, provider windows.GUID) (*etwSession, error) {
	sessionName := fmt.Sprintf("EDR_%s_%s", d.agentID[:min(8, len(d.agentID))], name)
	nameUTF16, err := windows.UTF16PtrFromString(sessionName)
	if err != nil {
		return nil, fmt.Errorf("encoding session name: %w", err)
	}

	sess, errSecure := d.startRealtimeTraceSession(sessionName, nameUTF16, provider, name, true)
	if errSecure == nil {
		d.secureTrace.Store(true)
		return sess, nil
	}
	sess, errStd := d.startRealtimeTraceSession(sessionName, nameUTF16, provider, name, false)
	if errStd != nil {
		return nil, fmt.Errorf("StartTraceW secure=%v standard=%v", errSecure, errStd)
	}
	return sess, nil
}

func (d *ETWDriver) startRealtimeTraceSession(sessionName string, nameUTF16 *uint16, provider windows.GUID, providerName string, secure bool) (*etwSession, error) {
	propSize := unsafe.Sizeof(etwTraceProperties{})
	bufSize := propSize + uintptr(len(sessionName)+1)*2
	buf := make([]byte, bufSize)

	props := (*etwTraceProperties)(unsafe.Pointer(&buf[0]))
	props.Wnode.BufferSize = uint32(bufSize)
	props.Wnode.Flags = wnodeFlagTracedGUID
	mode := uint32(eventTraceRealTimeMode)
	if secure {
		mode |= eventTraceSecureMode
	}
	props.LogFileMode = mode
	props.BufferSize = 64
	props.MinimumBuffers = 16
	props.MaximumBuffers = 64
	props.LoggerNameOffset = uint32(propSize)

	var sessionHandle uint64
	ret, _, _ := procStartTrace.Call(
		uintptr(unsafe.Pointer(&sessionHandle)),
		uintptr(unsafe.Pointer(nameUTF16)),
		uintptr(unsafe.Pointer(props)),
	)
	if ret != 0 {
		return nil, fmt.Errorf("StartTraceW: %w", windows.Errno(ret))
	}

	ret, _, _ = procEnableTraceEx2.Call(
		uintptr(sessionHandle),
		uintptr(unsafe.Pointer(&provider)),
		eventControlCodeEnableProvider,
		traceLevelVerbose,
		0xFFFFFFFFFFFFFFFF,
		0,
		0,
		0,
	)
	if ret != 0 {
		props2buf := make([]byte, bufSize)
		props2 := (*etwTraceProperties)(unsafe.Pointer(&props2buf[0]))
		props2.Wnode.BufferSize = uint32(bufSize)
		props2.LoggerNameOffset = uint32(propSize)
		procControlTrace.Call(uintptr(sessionHandle), 0, uintptr(unsafe.Pointer(props2)), eventTraceControlStop)
		return nil, fmt.Errorf("EnableTraceEx2: %w", windows.Errno(ret))
	}

	return &etwSession{
		name:          sessionName,
		nameUTF16:     nameUTF16,
		provider:      provider,
		providerName:  providerName,
		sessionHandle: sessionHandle,
	}, nil
}

func (d *ETWDriver) openAndProcess(s *etwSession) error {
	var logfile etwEventTraceLogfile
	logfile.LoggerName = uintptr(unsafe.Pointer(s.nameUTF16))
	logfile.ProcessTraceMode = processTraceModeRealTime | processTraceModeEventRecord
	logfile.EventRecordCb = etwCallbackPtr

	ret, _, err := procOpenTrace.Call(uintptr(unsafe.Pointer(&logfile)))
	if uint64(ret) == invalidProcesstraceHandle {
		return fmt.Errorf("OpenTraceW: %w", err)
	}
	s.traceHandle = uint64(ret)
	s.active.Store(true)

	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()

		handle := s.traceHandle
		procProcessTrace.Call(
			uintptr(unsafe.Pointer(&handle)),
			1,
			0,
			0,
		)
		s.active.Store(false)
		d.maybeRecoverETWSession(s)
	}()

	return nil
}

func (d *ETWDriver) ingestLoop(ctx context.Context) {
	defer d.ingestWg.Done()
	for {
		select {
		case <-ctx.Done():
			for {
				select {
				case rec := <-d.ingestCh:
					d.processCopiedRecord(&rec)
				default:
					return
				}
			}
		case rec := <-d.ingestCh:
			d.processCopiedRecord(&rec)
		}
	}
}

func (d *ETWDriver) processCopiedRecord(rec *etwRecordCopy) {
	var syn etwEventRecord
	syn.EventHeader = rec.EventHeader
	syn.BufferContext = rec.BufferContext
	syn.UserDataLength = uint16(len(rec.UserData))
	if len(rec.UserData) > 0 {
		syn.UserData = uintptr(unsafe.Pointer(&rec.UserData[0]))
	}
	d.handleEventRecord(&syn)
}

// maybeRecoverETWSession retries OpenTrace/ProcessTrace once after an unexpected session end.
func (d *ETWDriver) maybeRecoverETWSession(s *etwSession) {
	if s == nil || !d.running.Load() {
		return
	}
	if !s.recoveryAttempted.CompareAndSwap(false, true) {
		return
	}
	d.sessionRecoverAttempts.Add(1)
	go func() {
		time.Sleep(2 * time.Second)
		if !d.running.Load() {
			return
		}
		if err := d.openAndProcess(s); err != nil {
			d.errors.Add(1)
		}
	}()
}

func (d *ETWDriver) stopAllSessions() {
	for _, s := range d.sessions {
		d.stopSession(s)
	}
}

func (d *ETWDriver) stopSession(s *etwSession) {
	if !s.active.Load() {
		return
	}

	propSize := unsafe.Sizeof(etwTraceProperties{})
	bufSize := propSize + 256*2
	buf := make([]byte, bufSize)
	props := (*etwTraceProperties)(unsafe.Pointer(&buf[0]))
	props.Wnode.BufferSize = uint32(bufSize)
	props.LoggerNameOffset = uint32(propSize)

	procControlTrace.Call(
		uintptr(s.sessionHandle),
		0,
		uintptr(unsafe.Pointer(props)),
		eventTraceControlStop,
	)

	procCloseTrace.Call(uintptr(s.traceHandle))
	s.wg.Wait()
}

func etwEventRecordCallback(eventRecord uintptr) uintptr {
	d := globalETW.Load()
	if d == nil || d.ingestCh == nil {
		return 0
	}

	rec := (*etwEventRecord)(unsafe.Pointer(eventRecord))
	n := int(rec.UserDataLength)
	if n > maxETWUserDataCopy {
		n = maxETWUserDataCopy
	}
	var ud []byte
	if n > 0 && rec.UserData != 0 {
		src := unsafe.Slice((*byte)(unsafe.Pointer(rec.UserData)), rec.UserDataLength)
		if len(src) < n {
			n = len(src)
		}
		ud = make([]byte, n)
		copy(ud, src[:n])
	}
	copyRec := etwRecordCopy{
		EventHeader:   rec.EventHeader,
		BufferContext: rec.BufferContext,
		UserData:      ud,
	}
	select {
	case d.ingestCh <- copyRec:
	default:
		d.ingestDropped.Add(1)
	}
	return 0
}

func (d *ETWDriver) handleEventRecord(record *etwEventRecord) {
	d.received.Add(1)

	hdr := &record.EventHeader
	ts := filetimeToGoTime(hdr.TimeStamp)

	envelope := map[string]interface{}{
		"timestamp":   ts,
		"agent_id":    d.agentID,
		"pid":         hdr.ProcessId,
		"tid":         hdr.ThreadId,
		"provider":    guidString(hdr.ProviderId),
		"event_id":    hdr.EventDescriptor.Id,
		"opcode":      hdr.EventDescriptor.Opcode,
		"event_level": hdr.EventDescriptor.Level,
	}

	switch hdr.ProviderId {
	case kernelProcessGUID:
		envelope["type"] = events.EventProcess
		d.decodeProcessUserData(record, envelope)
	case kernelFileGUID:
		envelope["type"] = events.EventFile
		d.decodeFileUserData(record, envelope)
	case kernelNetworkGUID:
		envelope["type"] = events.EventNetwork
		d.decodeNetworkUserData(record, envelope)
	case dnsClientGUID:
		envelope["type"] = events.EventDNS
		d.decodeDNSClient(record, envelope)
	case kernelRegistryGUID:
		envelope["type"] = events.EventRegistry
		d.decodeKernelRegistry(record, envelope)
	case wmiActivityGUID:
		envelope["type"] = events.EventWMI
		d.decodeOpaqueETW(record, envelope)
	case powershellGUID:
		envelope["type"] = events.EventPowerShell
		d.decodeOpaqueETW(record, envelope)
	case kernelObjectGUID:
		envelope["type"] = events.EventPipe
		d.decodeOpaqueETW(record, envelope)
	case bitsClientGUID:
		envelope["type"] = events.EventBITS
		d.decodeOpaqueETW(record, envelope)
	case taskSchedulerGUID:
		envelope["type"] = events.EventTask
		d.decodeOpaqueETW(record, envelope)
	case threatIntelGUID:
		envelope["type"] = "injection"
		d.decodeOpaqueETW(record, envelope)
	default:
		envelope["type"] = events.EventProcess
	}

	data, err := json.Marshal(envelope)
	if err != nil {
		d.errors.Add(1)
		d.dropped.Add(1)
		return
	}
	if err := d.buf.Write(data); err != nil {
		d.dropped.Add(1)
		if errors.Is(err, ErrBufferFull) {
			d.errors.Add(1)
		}
		return
	}
	d.processed.Add(1)
}

func (d *ETWDriver) decodeProcessUserData(record *etwEventRecord, env map[string]interface{}) {
	ud := userDataSlice(record)
	if ud == nil {
		return
	}

	switch record.EventHeader.EventDescriptor.Id {
	case 1: // ProcessStart
		if len(ud) >= 20 {
			env["child_pid"] = binary.LittleEndian.Uint32(ud[0:4])
			env["parent_pid"] = binary.LittleEndian.Uint32(ud[12:16])
			env["session_id"] = binary.LittleEndian.Uint32(ud[16:20])
		}
		if len(ud) > 24 {
			env["image_name"] = extractUTF16String(ud[24:])
		}
	case 2: // ProcessStop
		if len(ud) >= 4 {
			env["exit_pid"] = binary.LittleEndian.Uint32(ud[0:4])
		}
	case 5: // ImageLoad
		// Microsoft-Windows-Kernel-Process ImageLoad payload (x64):
		//   ProcessId (u32), ImageBase (u64), ImageSize (u64), ImageName (utf16le)
		if len(ud) >= 4 {
			env["image_load_pid"] = binary.LittleEndian.Uint32(ud[0:4])
		}
		if len(ud) >= 20 {
			env["image_base"] = binary.LittleEndian.Uint64(ud[4:12])
			env["image_size"] = binary.LittleEndian.Uint64(ud[12:20])
		}
		if len(ud) > 20 {
			env["image_name"] = extractUTF16String(ud[20:])
		}
		env["type"] = events.EventModule
		env["op"] = "image_load"
	case 6: // ImageUnload
		if len(ud) >= 4 {
			env["image_unload_pid"] = binary.LittleEndian.Uint32(ud[0:4])
		}
		if len(ud) > 20 {
			env["image_name"] = extractUTF16String(ud[20:])
		}
		env["type"] = events.EventModule
		env["op"] = "image_unload"
	}
}

func (d *ETWDriver) kernelFileRemember(fo uint64, path string) {
	if fo == 0 || path == "" {
		return
	}
	d.fileObjMu.Lock()
	defer d.fileObjMu.Unlock()
	if d.fileObjPath == nil {
		d.fileObjPath = make(map[uint64]string)
	}
	capN := d.fileObjCap
	if capN <= 0 {
		capN = 65536
	}
	if _, exists := d.fileObjPath[fo]; !exists {
		d.fileObjFIFO = append(d.fileObjFIFO, fo)
		for len(d.fileObjFIFO) > capN {
			old := d.fileObjFIFO[0]
			d.fileObjFIFO = d.fileObjFIFO[1:]
			delete(d.fileObjPath, old)
		}
	}
	d.fileObjPath[fo] = path
}

func (d *ETWDriver) kernelFileLookup(fo uint64) string {
	d.fileObjMu.RLock()
	defer d.fileObjMu.RUnlock()
	if d.fileObjPath == nil {
		return ""
	}
	return d.fileObjPath[fo]
}

func (d *ETWDriver) decodeFileUserData(record *etwEventRecord, env map[string]interface{}) {
	ud := userDataSlice(record)
	if ud == nil || len(ud) < 8 {
		return
	}
	env["file_object"] = binary.LittleEndian.Uint64(ud[0:8])
	fn := ""
	if len(ud) > 8 {
		fn = extractUTF16String(ud[8:])
		env["file_name"] = fn
	}
	d.mu.RLock()
	cache := d.policy.KernelFileObjectCache
	d.mu.RUnlock()
	if cache {
		fo := binary.LittleEndian.Uint64(ud[0:8])
		if fn != "" {
			d.kernelFileRemember(fo, fn)
		} else if fo != 0 {
			if lp := d.kernelFileLookup(fo); lp != "" {
				env["file_name"] = lp
			}
		}
	}
}

func ip4FromDWordLE(v uint32) string {
	return net.IPv4(byte(v&0xff), byte((v>>8)&0xff), byte((v>>16)&0xff), byte((v>>24)&0xff)).String()
}

func (d *ETWDriver) decodeNetworkUserData(record *etwEventRecord, env map[string]interface{}) {
	ud := userDataSlice(record)
	if ud == nil {
		env["data_length"] = 0
		return
	}
	env["data_length"] = len(ud)

	// Microsoft-Windows-Kernel-Network IPv4 layout (TcpIp_V4_Header):
	//   uint32 PID        @0
	//   uint32 size       @4
	//   uint32 daddr      @8
	//   uint32 saddr      @12
	//   uint16 dport (BE) @16
	//   uint16 sport (BE) @18
	if len(ud) >= 20 {
		env["pid"] = binary.LittleEndian.Uint32(ud[0:4])
		env["size"] = binary.LittleEndian.Uint32(ud[4:8])
		daddr := binary.LittleEndian.Uint32(ud[8:12])
		saddr := binary.LittleEndian.Uint32(ud[12:16])
		dport := binary.BigEndian.Uint16(ud[16:18])
		sport := binary.BigEndian.Uint16(ud[18:20])
		env["src"] = ip4FromDWordLE(saddr)
		env["dst"] = ip4FromDWordLE(daddr)
		env["src_port"] = int(sport)
		env["dest_port"] = int(dport)
		// Map opcode → connect|accept|send|recv|disconnect for downstream rules.
		env["protocol"] = networkOpcodeName(record.EventHeader.EventDescriptor.Opcode)
		return
	}
	// Fallback for IPv6 / shorter records: still try to surface a PID so the
	// downstream lineage tracker can attribute the event to a process.
	if len(ud) >= 4 {
		env["pid"] = binary.LittleEndian.Uint32(ud[0:4])
	}
}

// networkOpcodeName maps Kernel-Network ETW opcodes to a textual operation
// name. The opcode table is documented in MSDN under TcpIp_V4_Header:
//
//	10/11 send, 12/13 recv, 14/15 disconnect/retransmit,
//	16 accept, 17 connect, 26 fail.
func networkOpcodeName(op uint8) string {
	switch op {
	case 10, 11:
		return "tcp:send"
	case 12, 13:
		return "tcp:recv"
	case 14, 15:
		return "tcp:disconnect"
	case 16:
		return "tcp:accept"
	case 17:
		return "tcp:connect"
	case 18, 19:
		return "tcp:reconnect"
	case 26:
		return "tcp:fail"
	}
	return "tcp"
}

func (d *ETWDriver) decodeOpaqueETW(record *etwEventRecord, env map[string]interface{}) {
	d.decodeStructuredETW(record, env)
}

func userDataSlice(record *etwEventRecord) []byte {
	if record.UserData == 0 || record.UserDataLength == 0 {
		return nil
	}
	return unsafe.Slice((*byte)(unsafe.Pointer(record.UserData)), record.UserDataLength)
}

func extractUTF16String(b []byte) string {
	if len(b) < 2 {
		return ""
	}
	n := len(b) / 2
	chars := make([]uint16, n)
	for i := 0; i < n; i++ {
		chars[i] = binary.LittleEndian.Uint16(b[i*2:])
		if chars[i] == 0 {
			return string(windows.UTF16ToString(chars[:i]))
		}
	}
	return string(windows.UTF16ToString(chars))
}

func filetimeToGoTime(ft int64) time.Time {
	if ft <= 0 {
		return time.Time{}
	}
	nsec := (ft - filetimeToUnixEpochDelta) * 100
	return time.Unix(0, nsec)
}

func guidString(g windows.GUID) string {
	return fmt.Sprintf("{%08X-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X}",
		g.Data1, g.Data2, g.Data3,
		g.Data4[0], g.Data4[1], g.Data4[2], g.Data4[3],
		g.Data4[4], g.Data4[5], g.Data4[6], g.Data4[7])
}
