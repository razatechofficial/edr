package localapi

import "strings"

// ServiceState is a service-manager state after per-OS normalisation.
//
// The three service managers describe the same sensor with three different
// vocabularies, and the UI used to test for one of them. launchctl reports a
// loaded job, systemd reports an active unit and the Windows SCM reports a
// running service; the macOS console therefore showed a healthy agent as
// unhealthy, because "loaded" contains none of "running", "started" or
// "active". Everything that has to make that judgement calls
// NormalizeServiceState and compares against these constants instead of
// matching substrings itself.
type ServiceState string

const (
	// ServiceRunning means the sensor process is up and supervised.
	ServiceRunning ServiceState = "running"
	// ServiceStarting means the service manager has accepted a start but the
	// sensor is not up yet.
	ServiceStarting ServiceState = "starting"
	// ServiceStopped means the service is installed and not running.
	ServiceStopped ServiceState = "stopped"
	// ServiceNotInstalled means the service manager does not know the unit.
	ServiceNotInstalled ServiceState = "not-installed"
	// ServiceUnknown means the probe itself failed, so the state is unread
	// rather than negative.
	ServiceUnknown ServiceState = "unknown"
)

// Healthy reports whether the state means the sensor is up. Only
// ServiceRunning qualifies: "starting" is not yet protecting the host.
func (s ServiceState) Healthy() bool { return s == ServiceRunning }

// String returns the canonical state name.
func (s ServiceState) String() string { return string(s) }

// serviceStateMaps documents the mapping from raw service-manager output to
// canonical states, per GOOS.
//
//	darwin   launchctl print system/com.razatech.edr-agent
//	         "running" (state = running in the job dump)  -> running
//	         "loaded"  (job present, state line not found) -> running
//	         "waiting", "spawn scheduled"                  -> starting
//	         "not running", "exited"                       -> stopped
//	         "not loaded" (launchctl print failed)         -> not-installed
//	linux    systemctl is-active edr-agent
//	         "active"                                      -> running
//	         "activating", "reloading"                     -> starting
//	         "deactivating", "inactive", "failed"          -> stopped
//	         "not-found" (no such unit)                    -> not-installed
//	         anything else, including "unknown"            -> unknown
//	windows  sc.exe query EDRAgent
//	         "running"                                     -> running
//	         "starting" (START_PENDING)                    -> starting
//	         "stopped", "stop_pending"                     -> stopped
//	         "installed" (query ok, state not recognised)  -> unknown
//	         "not installed"                               -> not-installed
//
// Any state name already canonical maps to itself on every OS, so
// normalising a normalised value is a no-op.
var serviceStateMaps = map[string]map[string]ServiceState{
	"darwin": {
		"loaded":          ServiceRunning,
		"not loaded":      ServiceNotInstalled,
		"notloaded":       ServiceNotInstalled,
		"unloaded":        ServiceNotInstalled,
		"waiting":         ServiceStarting,
		"spawn scheduled": ServiceStarting,
		"not running":     ServiceStopped,
		"exited":          ServiceStopped,
	},
	"linux": {
		"active":       ServiceRunning,
		"activating":   ServiceStarting,
		"reloading":    ServiceRunning,
		"deactivating": ServiceStopped,
		"inactive":     ServiceStopped,
		"failed":       ServiceStopped,
		"not-found":    ServiceNotInstalled,
		"not found":    ServiceNotInstalled,
	},
	"windows": {
		"running":       ServiceRunning,
		"start_pending": ServiceStarting,
		"starting":      ServiceStarting,
		"stop_pending":  ServiceStopped,
		"stopped":       ServiceStopped,
		"paused":        ServiceStopped,
		"installed":     ServiceUnknown,
		"not installed": ServiceNotInstalled,
	},
}

// canonicalServiceStates maps a state name to itself, and covers the names
// that mean the same thing on every platform.
var canonicalServiceStates = map[string]ServiceState{
	"running":       ServiceRunning,
	"started":       ServiceRunning,
	"starting":      ServiceStarting,
	"stopped":       ServiceStopped,
	"not-installed": ServiceNotInstalled,
	"not installed": ServiceNotInstalled,
	"unknown":       ServiceUnknown,
}

// NormalizeServiceState maps raw service-manager output for goos to a
// canonical ServiceState. An empty or unrecognised value is ServiceUnknown,
// never a healthy state: an unread probe must not look like a running sensor,
// and must not look like a stopped one either.
func NormalizeServiceState(goos, raw string) ServiceState {
	key := strings.ToLower(strings.TrimSpace(raw))
	if key == "" {
		return ServiceUnknown
	}
	if st, ok := serviceStateMaps[strings.ToLower(strings.TrimSpace(goos))][key]; ok {
		return st
	}
	if st, ok := canonicalServiceStates[key]; ok {
		return st
	}
	return ServiceUnknown
}
