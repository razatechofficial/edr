//go:build darwin && (!cgo || nosec)

package kernel

// macOS capability report for builds without the Endpoint Security bridge.
//
// This build has no kernel driver at all: ESFDriver.Start returns an error
// immediately (driver_darwin_nocgo.go) because the ESF client needs cgo. The
// report is still emitted, and still covers every canonical category, because
// a console that gets nothing back cannot tell "this agent is not monitoring"
// from "this agent did not answer". Every category comes back present=false
// with the reason, which is the correct and complete answer for this build.

// CapabilityReport reports that no kernel monitoring exists in this build.
// It implements CapabilityReporter.
func (d *ESFDriver) CapabilityReport() CapabilityReport {
	return emptyCapabilityReport(
		"esf",
		"agent was built without cgo or with the nosec tag, so the Endpoint Security Framework bridge is absent and no kernel monitoring is attached; rebuild with CGO_ENABLED=1 and without -tags nosec, and grant the EndpointSecurity entitlement",
	)
}
