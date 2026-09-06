package main

import (
	"fmt"
	"strings"

	"github.com/razatechofficial/edr/cmd/agentui/uistate"
)

func decorateHealth(st operatorStatus) (uistate.Health, uistate.Lamps) {
	svcOK := serviceHealthy(st.Service)
	queued := st.SpoolBytes >= 1<<20
	ingestUp := st.IngestConfigured && st.IngestOK && !queued
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
	} else if svcOK && st.IngestConfigured && !st.IngestOK {
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
	case strings.Contains(f, "certificate") || strings.Contains(f, "credentials") || strings.Contains(f, "enroll"):
		return "No device certificate. Enroll this PC with a new token."
	case strings.Contains(f, "502") || strings.Contains(f, "bad gateway"):
		return "Cloud ingest is unavailable (502). Local detections continue."
	case strings.Contains(f, "unavailable"):
		return "Cloud ingest is unavailable. Local detections continue."
	case strings.TrimSpace(fault) != "":
		msg := strings.TrimSpace(fault)
		if len(msg) > 120 {
			msg = msg[:120] + "…"
		}
		return "Ingest is not connected: " + msg
	default:
		return "Ingest is not connected. Local detections continue."
	}
}
