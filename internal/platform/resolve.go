package platform

import "os"

// firstExistingFile returns the first candidate that exists as a regular file.
func firstExistingFile(candidates []string) string {
	for _, p := range candidates {
		if p == "" {
			continue
		}
		st, err := os.Stat(p)
		if err == nil && !st.IsDir() {
			return p
		}
	}
	return ""
}

// ResolveConfigFile returns an on-disk agent config if one of the platform
// candidates exists, otherwise the preferred install path (so first-run
// installers still have a stable default).
func ResolveConfigFile() string {
	cands := ConfigFileCandidates()
	if p := firstExistingFile(cands); p != "" {
		return p
	}
	if len(cands) > 0 {
		return cands[0]
	}
	return ""
}

// ResolveAlertFile returns an existing alerts JSONL path or the preferred default.
func ResolveAlertFile() string {
	cands := AlertFileCandidates()
	if p := firstExistingFile(cands); p != "" {
		return p
	}
	if len(cands) > 0 {
		return cands[0]
	}
	return ""
}

// PreferredConfigFile is the canonical install-time config path (index 0).
func PreferredConfigFile() string {
	cands := ConfigFileCandidates()
	if len(cands) == 0 {
		return ""
	}
	return cands[0]
}
