//go:build darwin

package collector

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// PostureDarwinGatekeeper runs spctl --status.
func PostureDarwinGatekeeper() map[string]any {
	out, err := exec.Command("spctl", "--status").CombinedOutput()
	if err != nil {
		return map[string]any{"error": err.Error(), "detail": strings.TrimSpace(string(out))}
	}
	return map[string]any{"spctl_status": strings.TrimSpace(string(out))}
}

// PostureDarwinXProtectVersion reads XProtect version plist.
func PostureDarwinXProtectVersion() map[string]any {
	p := "/Library/Apple/System/Library/CoreServices/XProtect.bundle/Contents/Info.plist"
	b, err := os.ReadFile(p)
	if err != nil {
		return map[string]any{"error": err.Error()}
	}
	// Lightweight parse: look for CFBundleShortVersionString line after key
	s := string(b)
	if i := strings.Index(s, "CFBundleShortVersionString"); i >= 0 {
		rest := s[i:]
		if j := strings.Index(rest, "<string>"); j >= 0 {
			rest = rest[j+8:]
			if k := strings.Index(rest, "</string>"); k >= 0 {
				return map[string]any{"xprotect_plist_version": strings.TrimSpace(rest[:k])}
			}
		}
	}
	return map[string]any{"xprotect_plist": "present", "bytes": len(b)}
}

// PostureDarwinSystemExtensions runs systemextensionsctl list.
func PostureDarwinSystemExtensions() map[string]any {
	out, err := exec.Command("systemextensionsctl", "list").CombinedOutput()
	if err != nil {
		return map[string]any{"error": err.Error(), "detail": strings.TrimSpace(string(out))}
	}
	lines := strings.Split(string(out), "\n")
	n := 6
	if len(lines) < n {
		n = len(lines)
	}
	return map[string]any{"lines": len(lines), "sample": strings.TrimSpace(strings.Join(lines[:n], "\n"))}
}

// runOptionalDarwinPostureProbes runs macOS-specific probes selected in monitoring.posture_probes.
func (p *PostureCollector) runOptionalDarwinPostureProbes(ctx context.Context) {
	if p == nil || len(p.cfg.Monitoring.PostureProbes) == 0 {
		return
	}
	out := map[string]any{}
	for _, raw := range p.cfg.Monitoring.PostureProbes {
		name := strings.ToLower(strings.TrimSpace(raw))
		if ctx.Err() != nil {
			break
		}
		switch name {
		case "posture_darwin_gatekeeper":
			out[name] = PostureDarwinGatekeeper()
		case "posture_darwin_xprotect":
			out[name] = PostureDarwinXProtectVersion()
		case "posture_darwin_sysext":
			out[name] = PostureDarwinSystemExtensions()
		case "posture_darwin_codesign":
			out[name] = PostureDarwinCodesignSample()
		case "posture_darwin_scdynamicstore":
			var snap map[string]any
			RunSCDynamicStoreRouteProbe(ctx, func(m map[string]any) { snap = m })
			out[name] = snap
		default:
			out[name] = map[string]any{"status": "unknown_probe"}
		}
	}
	p.mu.Lock()
	p.probeOut = out
	p.mu.Unlock()
}

// PostureDarwinCodesignSample verifies a small set of system binaries.
func PostureDarwinCodesignSample() map[string]any {
	paths := []string{"/usr/bin/true", "/bin/ls"}
	res := map[string]any{}
	for _, p := range paths {
		out, err := exec.Command("codesign", "--display", "--verbose=4", p).CombinedOutput()
		if err != nil {
			res[filepath.Base(p)] = map[string]any{"error": err.Error()}
			continue
		}
		res[filepath.Base(p)] = map[string]any{"ok": true, "detail_len": len(out)}
	}
	return res
}
