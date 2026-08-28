package uistate

// Screen routing: setup (attended installer) → token → identity → receipt
// → OS grants → every-launch preflight → tray.

type Screen int

const (
	Enroll Screen = iota
	Identity
	Receipt
	Permissions
	Preflight
	Dash
	Setup
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
