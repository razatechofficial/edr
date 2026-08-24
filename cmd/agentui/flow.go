package main

// Screen routing follows the standard EDR onboarding state machine:
// not enrolled → enrollment → preflight → dashboard. Already-enrolled
// devices skip to the dashboard unless a blocking permission check remains.

type screenID int

const (
	screenEnroll screenID = iota
	screenPreflight
	screenDash
)

type healthKind int

const (
	healthOffline healthKind = iota
	healthDegraded
	healthContained
	healthSecure
)

func initialScreen(enrolled, needsPreflight bool) screenID {
	if !enrolled {
		return screenEnroll
	}
	if needsPreflight {
		return screenPreflight
	}
	return screenDash
}

func classifyHealth(enrolled, serviceOK, apiOK, isolated bool) healthKind {
	if isolated {
		return healthContained
	}
	if !enrolled || !serviceOK {
		return healthOffline
	}
	if !apiOK {
		return healthDegraded
	}
	return healthSecure
}

func healthCopy(k healthKind) (title, subtitle string) {
	switch k {
	case healthSecure:
		return "SECURE", "System protected"
	case healthContained:
		return "CONTAINED", "Host isolation is active"
	case healthDegraded:
		return "DEGRADED", "Sensor running without a control API"
	default:
		return "OFFLINE", "Sensor is not streaming"
	}
}
