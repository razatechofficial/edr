package main

import (
	"fmt"

	"github.com/razatechofficial/edr/cmd/agentui/uistate"
)

func decorateHealth(st operatorStatus) (uistate.Health, uistate.Lamps) {
	k := uistate.ClassifyHealth(st.Enrolled, serviceHealthy(st.Service), st.ControlAPI == "ok", st.Isolated)
	lamps := uistate.HealthCopy(k)
	if needsOSGrants() {
		lamps.Title = "Needs attention"
		lamps.Sensor = "Limited"
		switch {
		case isDarwin():
			lamps.Banner = "Full Disk Access was revoked."
		case isWindows():
			lamps.Banner = "Firewall or service rights were revoked."
		default:
			lamps.Banner = "Required capabilities were revoked."
		}
		k = uistate.Degraded
	}
	if st.SpoolBytes >= 1<<20 {
		lamps.Banner = fmt.Sprintf("Telemetry queued (%s). Local detections continue.", formatBytesMB(st.SpoolBytes))
		if k == uistate.Protected {
			k = uistate.Degraded
			lamps.Title = "On this device"
			lamps.Stream = "Queued"
		}
	}
	if expiring, days := certExpiring(st.CertExpiry); expiring && k == uistate.Protected {
		lamps.Banner = fmt.Sprintf("Certificate expires in %d days.", days)
		k = uistate.Degraded
	}
	return k, lamps
}
