package actions

// MergeAllowList puts agentIP first, deduplicates, and is used by isolate tests and OS implementations.
func MergeAllowList(agentIP string, allow []string) []string {
	seen := make(map[string]struct{})
	var out []string
	if agentIP != "" {
		seen[agentIP] = struct{}{}
		out = append(out, agentIP)
	}
	for _, s := range allow {
		if s == "" {
			continue
		}
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	return out
}
