package collector

import "runtime"

// kernelTierCapabilityHealth builds a monitoring_health.json row for kernel when
// no driver is attached (rare GOOS tier_minimal_noop or main-OS capability_probe).
func kernelTierCapabilityHealth(source string, k kernelCapability, reasonCode string) map[string]any {
	rc := reasonCode
	if rc == "" {
		rc = "capability_probe"
	}
	notes := rc + "; " + k.ReasonSummary
	src := MonitoringSource{
		Name:      "kernel",
		OS:        runtime.GOOS,
		Source:    source,
		Status:    "absent",
		LastError: rc,
		Notes:     notes,
	}.ToMap()
	src["reason"] = rc
	src["goos"] = k.GOOS
	src["cgo_enabled"] = k.CGOSupported
	src["running_as_root"] = k.RunningAsRoot
	src["dtrace_present"] = k.DtracePresent
	if k.DtracePath != "" {
		src["dtrace_path"] = k.DtracePath
	}
	src["bpf_supported"] = k.BPFSupported
	src["go_version"] = k.RuntimeGoVersion
	return src
}
