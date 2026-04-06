package events

// EventType identifies the category of a kernel or system event.
type EventType string

const (
	EventProcess  EventType = "process"
	EventFile     EventType = "file"
	EventNetwork  EventType = "network"
	EventRegistry EventType = "registry"
	EventMemory   EventType = "memory"
	EventDNS      EventType = "dns"
	EventAuth     EventType = "auth"
	EventModule   EventType = "module"
	EventMount    EventType = "mount"
	EventPtrace   EventType = "ptrace"
	EventSignal   EventType = "signal"
)
