package ocsf

// EnrichDetectionMap builds an OCSF-native activation map for detection rules.
func EnrichDetectionMap(in map[string]interface{}) map[string]interface{} {
	if len(in) == 0 {
		return in
	}
	env := OCSFEnvelopeFromFlat(in)
	if env == nil {
		return in
	}
	return CELActivationMap(env)
}
