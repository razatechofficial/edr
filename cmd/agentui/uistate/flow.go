package uistate

// Screen routing (native package install only — no custom Setup wizard):
// token → identity → receipt → OS grants → every-launch preflight → tray.
// Setup is only the orphan "not installed" message after a broken uninstall.

type Screen int

const (
	Enroll Screen = iota
	Identity
	Receipt
	Permissions
	Preflight
	Dash
	Setup // orphan / not-installed message only (never EULA copy-files)
)

type Health int

const (
	Unprotected Health = iota
	Degraded
	Contained
	Protected
)

func InitialScreen(installed, enrolled, needsGrants, serviceOK bool) Screen {
	if !installed {
		return Setup
	}
	if !enrolled {
		return Enroll
	}
	if needsGrants {
		return Permissions
	}
	if !serviceOK {
		return Preflight
	}
	return Dash
}

// Route is the enterprise entry state machine (CrowdStrike / Defender / NIST CM-2):
//
//	not installed                         → Setup (orphan: use MSI/pkg/deb)
//	installed, not enrolled               → Enroll (token)
//	enrolled, OS grants missing           → Permissions (FDA / firewall / PPPC)
//	enrolled, grants OK, sensor stopped   → Preflight (register/start service)
//	enrolled, sensor running              → Dash
//
// fromSetup is ignored: attended Setup.exe / --setup are removed from the
// product path. Tray Open must call Route again — never skip to Dash while
// the service is missing.
func Route(fromSetup, installed, enrolled, needsGrants, serviceOK bool) Screen {
	_ = fromSetup
	if !installed {
		return Setup
	}
	return InitialScreen(true, enrolled, needsGrants, serviceOK)
}

// ClassifyHealth splits sensor (local monitoring) from stream (ingest).
// A running sensor with a down stream is degraded, not unprotected (NIST SI-4).
func ClassifyHealth(enrolled, serviceOK, streamOK, isolated bool) Health {
	if isolated {
		return Contained
	}
	if !enrolled || !serviceOK {
		return Unprotected
	}
	if !streamOK {
		return Degraded
	}
	return Protected
}

type Lamps struct {
	Title  string
	Sensor string
	Stream string
	Banner string
}

func HealthCopy(k Health) Lamps {
	switch k {
	case Protected:
		return Lamps{Title: "Protected", Sensor: "Running", Stream: "Live"}
	case Contained:
		return Lamps{Title: "Contained", Sensor: "Running", Stream: "Live", Banner: "Host isolation is active."}
	case Degraded:
		return Lamps{
			Title:  "On this device",
			Sensor: "Running",
			Stream: "Idle",
			Banner: "Ingest is not connected. Local detections continue.",
		}
	default:
		return Lamps{Title: "Unprotected", Sensor: "Stopped", Stream: "Idle", Banner: "This host is not monitored."}
	}
}
