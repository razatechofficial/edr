package uistate

// Screen routing follows the standard EDR onboarding state machine:
// not enrolled → enrollment → preflight → dashboard. Already-enrolled
// devices skip to the dashboard unless a blocking permission check remains.

type Screen int

const (
	Enroll Screen = iota
	Preflight
	Dash
)

type Health int

const (
	Offline Health = iota
	Degraded
	Contained
	Secure
)

func InitialScreen(enrolled, needsPreflight bool) Screen {
	if !enrolled {
		return Enroll
	}
	if needsPreflight {
		return Preflight
	}
	return Dash
}

func ClassifyHealth(enrolled, serviceOK, apiOK, isolated bool) Health {
	if isolated {
		return Contained
	}
	if !enrolled || !serviceOK {
		return Offline
	}
	if !apiOK {
		return Degraded
	}
	return Secure
}

func HealthCopy(k Health) (title, subtitle string) {
	switch k {
	case Secure:
		return "SECURE", "System protected"
	case Contained:
		return "CONTAINED", "Host isolation is active"
	case Degraded:
		return "DEGRADED", "Sensor running without a control API"
	default:
		return "OFFLINE", "Sensor is not streaming"
	}
}
