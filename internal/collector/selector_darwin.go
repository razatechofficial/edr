//go:build darwin

package collector

import (
	"errors"
	"os"
	"strings"
	"sync"
)

// DarwinSourceSelection records which monitoring sources are usable on this
// macOS host. It is computed once at agent startup; the result is reported
// in monitoring_health.json so operators can see which path is active.
type DarwinSourceSelection struct {
	ESFAvailable   bool   // true when ES client could be created
	ESFError       string // populated when ESFAvailable is false
	UserlandActive bool   // true when fallback userland sources are used
	Reason         string // human-readable explanation
}

// SelectDarwinSources decides between ESF and userland sources at startup.
// It does not start any source; it just probes capability so the agent can
// wire the selected ones. tryESF is a small adapter so this file does not
// need to import internal/kernel directly.
func SelectDarwinSources(allowFallback bool, tryESF func() error) DarwinSourceSelection {
	sel := DarwinSourceSelection{}
	if os.Geteuid() != 0 {
		sel.ESFError = "esf: not privileged (must run as root)"
		if allowFallback {
			sel.UserlandActive = true
			sel.Reason = "ESF requires root; falling back to proc_listpids + sysctl + FSEvents"
			return sel
		}
		sel.Reason = "ESF requires root and userland fallback disabled"
		return sel
	}
	if tryESF == nil {
		sel.ESFError = "esf: probe function not provided"
		if allowFallback {
			sel.UserlandActive = true
			sel.Reason = "ESF probe missing; using userland fallback"
		}
		return sel
	}
	if err := tryESF(); err != nil {
		sel.ESFError = err.Error()
		if allowFallback {
			sel.UserlandActive = true
			sel.Reason = "ESF unavailable: " + summarizeESFError(err) + "; using userland fallback"
			return sel
		}
		sel.Reason = "ESF unavailable and userland fallback disabled"
		return sel
	}
	sel.ESFAvailable = true
	sel.Reason = "ESF available"
	return sel
}

// SelectionStatus translates a DarwinSourceSelection into a MonitoringSource
// record so it surfaces in monitoring_health.json alongside per-source EPS
// and drop counters.
func (s DarwinSourceSelection) SelectionStatus() MonitoringSource {
	src := MonitoringSource{
		Name:   "selector",
		OS:     "darwin",
		Source: "esf-or-userland",
	}
	switch {
	case s.ESFAvailable:
		src.Status = "healthy"
		src.LastError = ""
	case s.UserlandActive:
		src.Status = "degraded"
		src.LastError = s.ESFError
	default:
		src.Status = "unavailable"
		src.LastError = s.ESFError
	}
	return src
}

// darwinSelectionGate prevents the same selection probe from running multiple
// times per process; collectors that observe selection during construction
// share a single sync.Once.
type darwinSelectionGate struct {
	once sync.Once
	val  DarwinSourceSelection
}

func (g *darwinSelectionGate) get(allowFallback bool, tryESF func() error) DarwinSourceSelection {
	g.once.Do(func() {
		g.val = SelectDarwinSources(allowFallback, tryESF)
	})
	return g.val
}

func summarizeESFError(err error) string {
	if err == nil {
		return ""
	}
	if errors.Is(err, os.ErrPermission) {
		return "permission denied"
	}
	msg := err.Error()
	if i := strings.IndexByte(msg, ':'); i >= 0 && i < len(msg)-1 {
		msg = strings.TrimSpace(msg[i+1:])
	}
	return msg
}
