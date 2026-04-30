package forwarder

import (
	"net"
	"strings"

	"github.com/razatechofficial/edr/internal/schema"
)

// CortexObservables groups IOC-shaped strings expected by Cortex/TheHive analyzers.
// Mirrors docs/integrations/cortex_misp_observable_contract.md.
func CortexObservables(a schema.Alert) map[string][]string {
	out := map[string][]string{}
	add := func(k, v string) {
		v = strings.TrimSpace(v)
		if v == "" {
			return
		}
		out[k] = append(out[k], v)
	}
	hash := strings.ToLower(strings.TrimSpace(a.FileSHA256))
	if hash != "" {
		add("hash", hash)
	}
	if ip := strings.TrimSpace(a.DestIP); ip != "" && net.ParseIP(ip) != nil {
		add("ip", ip)
	}
	if ip := strings.TrimSpace(a.SourceIP); ip != "" && net.ParseIP(ip) != nil {
		add("ip", ip)
	}
	if dom := strings.TrimSpace(a.Domain); dom != "" {
		dom = strings.TrimSuffix(strings.ToLower(dom), ".")
		add("domain", dom)
	}
	if u := strings.TrimSpace(a.URL); u != "" {
		add("url", u)
	}
	return dedupeSlices(out)
}

func dedupeSlices(m map[string][]string) map[string][]string {
	for k, sl := range m {
		seen := map[string]struct{}{}
		var next []string
		for _, s := range sl {
			s = strings.TrimSpace(s)
			if s == "" {
				continue
			}
			if _, ok := seen[s]; ok {
				continue
			}
			seen[s] = struct{}{}
			next = append(next, s)
		}
		m[k] = next
	}
	return m
}
