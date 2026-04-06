//go:build windows

// Package etw provides a wrapper around Windows Event Tracing for Windows (ETW)
// for consuming real-time kernel and security events in the EDR agent.
package etw

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Provider GUIDs for the ETW providers consumed by the EDR agent.
var (
	// ProviderProcess is the Microsoft-Windows-Kernel-Process provider.
	ProviderProcess = windows.GUID{
		Data1: 0x22FB2CD6,
		Data2: 0x0E7B,
		Data3: 0x422B,
		Data4: [8]byte{0xA0, 0xC7, 0x2F, 0xAD, 0x1F, 0xD0, 0xE7, 0x16},
	}

	// ProviderFile is the Microsoft-Windows-Kernel-File provider.
	ProviderFile = windows.GUID{
		Data1: 0xEDD08927,
		Data2: 0x9CC4,
		Data3: 0x4E65,
		Data4: [8]byte{0xB9, 0x70, 0xC2, 0x56, 0x0F, 0xB5, 0xC2, 0x89},
	}

	// ProviderNetwork is the Microsoft-Windows-Kernel-Network provider.
	ProviderNetwork = windows.GUID{
		Data1: 0x7DD42A49,
		Data2: 0x5329,
		Data3: 0x4832,
		Data4: [8]byte{0x8D, 0xFD, 0x43, 0xD9, 0x79, 0x15, 0x3A, 0x88},
	}

	// ProviderRegistry is the Microsoft-Windows-Kernel-Registry provider.
	ProviderRegistry = windows.GUID{
		Data1: 0x70EB4F03,
		Data2: 0xC1DE,
		Data3: 0x4F73,
		Data4: [8]byte{0xA0, 0x51, 0x33, 0xD1, 0x3D, 0x50, 0x68, 0xD7},
	}

	// ProviderSecurity is the Microsoft-Windows-Security-Auditing provider.
	ProviderSecurity = windows.GUID{
		Data1: 0x54849625,
		Data2: 0x5478,
		Data3: 0x4994,
		Data4: [8]byte{0xA5, 0xBA, 0x3E, 0x3B, 0x03, 0x28, 0xC3, 0x0D},
	}
)

const (
	eventTraceRealTimeMode = 0x00000100
	processTraceModeRealTime = 0x00000100
	processTraceModeEventRecord = 0x10000000
	wnodeClientCtx1QPC     = 1
	invalidHandle          = ^uintptr(0)
)

// EventRecord mirrors the native EVENT_RECORD structure layout.
type EventRecord struct {
	EventHeader    EventHeader
	BufferContext   EventTraceBufferContext
	ExtendedDataCount uint16
	UserDataLength    uint16
	ExtendedData      uintptr
	UserData          uintptr
	UserContext        uintptr
}

// EventHeader mirrors the native EVENT_HEADER structure layout.
type EventHeader struct {
	Size            uint16
	HeaderType      uint16
	Flags           uint16
	EventProperty   uint16
	ThreadID        uint32
	ProcessID       uint32
	TimeStamp       int64
	ProviderID      windows.GUID
	EventDescriptor EventDescriptor
	_               uint64
	ActivityID      windows.GUID
}

// EventDescriptor describes an individual ETW event's identity.
type EventDescriptor struct {
	ID      uint16
	Version uint8
	Channel uint8
	Level   uint8
	Opcode  uint8
	Task    uint16
	Keyword uint64
}

// EventTraceBufferContext contains processor and logger context.
type EventTraceBufferContext struct {
	ProcessorIndex uint16
	LoggerID       uint16
}

// EventCallback is the function signature for receiving parsed ETW events.
type EventCallback func(record *EventRecord)

// Session wraps a single ETW real-time trace session.
type Session struct {
	name         string
	providerGUID windows.GUID
	sessionHandle uintptr
	traceHandle   uintptr
	callback     EventCallback
	running      atomic.Bool
	mu           sync.Mutex
	wg           sync.WaitGroup
}

// NewSession creates a new ETW session targeting the given provider.
// The session name must be unique across the system.
func NewSession(name string, providerGUID windows.GUID) (*Session, error) {
	if name == "" {
		return nil, errors.New("etw: session name must not be empty")
	}
	return &Session{
		name:          name,
		providerGUID:  providerGUID,
		sessionHandle: invalidHandle,
		traceHandle:   invalidHandle,
	}, nil
}

// Start begins real-time event consumption. It blocks until the context is
// cancelled or Stop is called. The callback is invoked for each event on the
// processing goroutine.
func (s *Session) Start(ctx context.Context, callback EventCallback) error {
	s.mu.Lock()
	if s.running.Load() {
		s.mu.Unlock()
		return errors.New("etw: session already running")
	}
	s.callback = callback
	s.mu.Unlock()

	if err := s.startTrace(); err != nil {
		return fmt.Errorf("etw: start trace: %w", err)
	}

	if err := s.enableProvider(); err != nil {
		s.stopTrace()
		return fmt.Errorf("etw: enable provider: %w", err)
	}

	s.running.Store(true)

	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		s.processTrace()
	}()

	go func() {
		<-ctx.Done()
		s.Stop()
	}()

	return nil
}

// Stop terminates the trace session and waits for the processing goroutine
// to drain.
func (s *Session) Stop() error {
	if !s.running.CompareAndSwap(true, false) {
		return nil
	}

	s.stopTrace()
	s.wg.Wait()
	return nil
}

// startTrace sets up the real-time trace session via StartTrace.
func (s *Session) startTrace() error {
	namePtr, err := windows.UTF16PtrFromString(s.name)
	if err != nil {
		return err
	}

	const propSize = unsafe.Sizeof(eventTraceProperties{})
	const nameMax = 256
	bufSize := propSize + nameMax*2

	buf := make([]byte, bufSize)
	props := (*eventTraceProperties)(unsafe.Pointer(&buf[0]))
	props.Wnode.BufferSize = uint32(bufSize)
	props.Wnode.Flags = 0x00020000 // WNODE_FLAG_TRACED_GUID
	props.Wnode.ClientContext = wnodeClientCtx1QPC
	props.LogFileMode = eventTraceRealTimeMode
	props.LoggerNameOffset = uint32(propSize)

	r, _, e := procStartTraceW.Call(
		uintptr(unsafe.Pointer(&s.sessionHandle)),
		uintptr(unsafe.Pointer(namePtr)),
		uintptr(unsafe.Pointer(props)),
	)
	if r != 0 {
		return fmt.Errorf("StartTraceW failed: %w", e)
	}
	return nil
}

// enableProvider enables the provider on the session.
func (s *Session) enableProvider() error {
	r, _, e := procEnableTraceEx2.Call(
		s.sessionHandle,
		uintptr(unsafe.Pointer(&s.providerGUID)),
		1, // EVENT_CONTROL_CODE_ENABLE_PROVIDER
		5, // TRACE_LEVEL_VERBOSE
		0, // MatchAnyKeyword (all)
		0, // MatchAllKeyword
		0, // Timeout
		0, // EnableParameters
	)
	if r != 0 {
		return fmt.Errorf("EnableTraceEx2 failed: %w", e)
	}
	return nil
}

// processTrace opens and processes the trace in real-time.
func (s *Session) processTrace() {
	namePtr, err := windows.UTF16PtrFromString(s.name)
	if err != nil {
		return
	}

	logfile := eventTraceLogfile{
		LoggerName:      namePtr,
		ProcessTraceMode: processTraceModeRealTime | processTraceModeEventRecord,
		Callback:        windows.NewCallback(s.eventRecordCallback),
	}

	handle, _, _ := procOpenTraceW.Call(uintptr(unsafe.Pointer(&logfile)))
	if handle == invalidHandle {
		return
	}
	s.traceHandle = handle

	procProcessTrace.Call(
		uintptr(unsafe.Pointer(&s.traceHandle)),
		1,
		0,
		0,
	)

	procCloseTrace.Call(s.traceHandle)
	s.traceHandle = invalidHandle
}

// stopTrace tears down the running session.
func (s *Session) stopTrace() {
	if s.traceHandle != invalidHandle {
		procCloseTrace.Call(s.traceHandle)
		s.traceHandle = invalidHandle
	}

	if s.sessionHandle != invalidHandle {
		namePtr, err := windows.UTF16PtrFromString(s.name)
		if err != nil {
			return
		}

		const propSize = unsafe.Sizeof(eventTraceProperties{})
		const nameMax = 256
		bufSize := propSize + nameMax*2

		buf := make([]byte, bufSize)
		props := (*eventTraceProperties)(unsafe.Pointer(&buf[0]))
		props.Wnode.BufferSize = uint32(bufSize)
		props.LoggerNameOffset = uint32(propSize)

		procControlTraceW.Call(
			s.sessionHandle,
			uintptr(unsafe.Pointer(namePtr)),
			uintptr(unsafe.Pointer(props)),
			1, // EVENT_TRACE_CONTROL_STOP
		)
		s.sessionHandle = invalidHandle
	}
}

func (s *Session) eventRecordCallback(record *EventRecord) uintptr {
	if s.callback != nil {
		s.callback(record)
	}
	return 0
}

// Native ETW structures used for syscalls.

type wnodeHeader struct {
	BufferSize    uint32
	ProviderId    uint32
	_             uint64
	_             uint64
	Guid          windows.GUID
	ClientContext uint32
	Flags         uint32
}

type eventTraceProperties struct {
	Wnode               wnodeHeader
	BufferSize          uint32
	MinimumBuffers      uint32
	MaximumBuffers      uint32
	MaximumFileSize     uint32
	LogFileMode         uint32
	FlushTimer          uint32
	EnableFlags         uint32
	_                   int32
	_                   uint32
	_                   uint32
	LogFileNameOffset   uint32
	LoggerNameOffset    uint32
}

type eventTraceLogfile struct {
	LoggerName       *uint16
	LogFileName      *uint16
	CurrentTime      int64
	BuffersRead      uint32
	ProcessTraceMode uint32
	CurrentEvent     [80]byte // EVENT_TRACE placeholder
	LogfileHeader    [296]byte // TRACE_LOGFILE_HEADER placeholder
	BufferCallback   uintptr
	BufferSize       uint32
	Filled           uint32
	_                uint32
	Callback         uintptr
	IsKernelTrace    uint32
	Context          uintptr
}

// Lazy-loaded advapi32 procedures for ETW management.
var (
	modAdvapi32         = windows.NewLazySystemDLL("advapi32.dll")
	procStartTraceW     = modAdvapi32.NewProc("StartTraceW")
	procControlTraceW   = modAdvapi32.NewProc("ControlTraceW")
	procEnableTraceEx2  = modAdvapi32.NewProc("EnableTraceEx2")
	procOpenTraceW      = modAdvapi32.NewProc("OpenTraceW")
	procProcessTrace    = modAdvapi32.NewProc("ProcessTrace")
	procCloseTrace      = modAdvapi32.NewProc("CloseTrace")
)
