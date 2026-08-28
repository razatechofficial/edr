package main

import (
	"fmt"
	"strings"

	"github.com/razatechofficial/edr/cmd/agentui/uistate"
)

func decorateHealth(st operatorStatus) (uistate.Health, uistate.Lamps) {
	svcOK := serviceHealthy(st.Service)
	queued := st.SpoolBytes >= 1<<20
	ingestUp := st.IngestConfigured && st.IngestEnv && st.IngestOK && !queued
	k := uistate.ClassifyHealth(st.Enrolled, svcOK, ingestUp, st.Isolated)
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
	if queued {
		lamps.Banner = fmt.Sprintf("Telemetry queued (%s). Local detections continue.", formatBytesMB(st.SpoolBytes))
		lamps.Stream = "Queued"
		if k == uistate.Protected {
			k = uistate.Degraded
			lamps.Title = "On this device"
		}
	} else if svcOK && st.IngestConfigured && st.IngestEnv && !st.IngestOK {
		lamps.Title = "Reconnecting"
		lamps.Stream = "Retrying"
		lamps.Banner = ingestIdleBanner(st.IngestConfigured, st.IngestEnv, st.IngestFault)
		if st.SpoolBytes > 0 {
			lamps.Banner = fmt.Sprintf("Ingest dropped (%s spool). Sensor still monitoring.", formatBytesMB(st.SpoolBytes))
		}
		k = uistate.Degraded
	} else if svcOK && !ingestUp {
		lamps.Stream = "Idle"
		lamps.Banner = ingestIdleBanner(st.IngestConfigured, st.IngestEnv, st.IngestFault)
	}
	if expiring, days := certExpiring(st.CertExpiry); expiring && k == uistate.Protected {
		lamps.Banner = fmt.Sprintf("Certificate expires in %d days.", days)
		k = uistate.Degraded
	}
	return k, lamps
}

func ingestIdleBanner(configured, env bool, fault string) string {
	if !configured {
		return "Ingest is not configured. Local detections continue."
	}
	if !env {
		return "Ingest is not enabled on the sensor. Connect stream to send telemetry."
	}
	f := strings.ToLower(fault)
	switch {
	case strings.Contains(f, "502") || strings.Contains(f, "bad gateway"):
		return "Cloud ingest is unavailable (502). The sensor is running on this Mac."
	case strings.Contains(f, "unavailable"):
		return "Cloud ingest is unavailable. Local detections continue."
	default:
		return "Ingest is not connected. Local detections continue."
	}
}
