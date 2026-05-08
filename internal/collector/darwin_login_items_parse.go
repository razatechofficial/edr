package collector

import "strings"

// splitDarwinLoginItemPaths parses osascript output from:
// tell application "System Events" to get POSIX path of every login item
func splitDarwinLoginItemPaths(out string) []string {
	var paths []string
	for _, ln := range strings.Split(out, ",") {
		p := strings.TrimSpace(strings.Trim(ln, `"'`+"\n "))
		if p != "" {
			paths = append(paths, p)
		}
	}
	return paths
}
