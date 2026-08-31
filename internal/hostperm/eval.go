package hostperm

import "runtime"

// IsGrantID is true for OS permission rows (FDA, sysext, firewall), not
// persistence/service/spool. Those belong on the every-launch preflight.
func IsGrantID(id string) bool {
	switch id {
	case IDFDA, IDSysExt, IDNetExt, IDFirewall, IDCaps:
		return true
	default:
		return false
	}
}

// IsPromptID is true for rows the first-run grants screen should show and
// open System Settings for: OS grants plus the login-item / startup prompt.
func IsPromptID(id string) bool {
	return IsGrantID(id) || id == IDLoginUI
}

// GrantItems returns the OS-grant subset of a catalog report.
func GrantItems(r Report) []Item {
	out := make([]Item, 0, 4)
	for _, it := range r.Items {
		if IsGrantID(it.ID) {
			out = append(out, it)
		}
	}
	return out
}

// PromptItems is the first-run grants list: FDA / firewall / extensions
// plus Login Items so the operator is asked to allow the console at login.
func PromptItems(r Report) []Item {
	out := make([]Item, 0, 6)
	for _, it := range r.Items {
		if IsPromptID(it.ID) {
			out = append(out, it)
		}
	}
	return out
}

// GrantsReady is true when every required OS grant is OK or not applicable.
func GrantsReady(r Report) bool {
	for _, it := range r.Items {
		if !IsGrantID(it.ID) || !it.Required {
			continue
		}
		if it.Status != StatusOK && it.Status != StatusNA {
			return false
		}
	}
	return true
}

// Evaluate runs the OS catalog. Missing optional rows (system extension not
// shipped) are StatusNA and do not block start.
func Evaluate() Report {
	return evaluate(false)
}

// EvaluateQuick skips slow optional probes (systemextensionsctl) for the tray poll.
func EvaluateQuick() Report {
	return evaluate(true)
}

func evaluate(quick bool) Report {
	items := catalog()
	for i := range items {
		if quick && (items[i].ID == IDSysExt || items[i].ID == IDNetExt) {
			items[i] = na(items[i], "Checked on the permissions screen.")
			continue
		}
		items[i] = evaluateItem(items[i])
	}
	r := Report{OS: runtime.GOOS, Items: items}
	r.AllRequired = true
	for _, it := range items {
		if !it.Required {
			continue
		}
		switch it.Status {
		case StatusOK, StatusNA:
		default:
			r.AllRequired = false
			if it.Status == StatusAction || it.Status == StatusFail {
				r.NeedsAction = true
			}
		}
	}
	return r
}

// EnsurePromptedItems registers OS login/startup hooks so the system can
// show its native prompt (macOS Login Items, etc.) before Recheck.
func EnsurePromptedItems() {
	ensureLoginItem()
	revealSensorForFDA()
}

// NeedsGrants is true when a required OS grant (FDA / firewall / caps) is
// missing or revoked. Boot, service, and spool are preflight checks.
func NeedsGrants() bool {
	return !GrantsReady(EvaluateQuick())
}

// RequiredIDs returns catalog IDs that must be green before Start.
func RequiredIDs(r Report) []string {
	var out []string
	for _, it := range r.Items {
		if it.Required && it.Status != StatusOK && it.Status != StatusNA {
			out = append(out, it.ID)
		}
	}
	return out
}

func fail(it Item, detail string) Item {
	it.Status = StatusFail
	it.Detail = detail
	return it
}

func action(it Item, detail string) Item {
	it.Status = StatusAction
	it.Detail = detail
	return it
}

func ok(it Item, detail string) Item {
	it.Status = StatusOK
	it.Detail = detail
	return it
}

func na(it Item, detail string) Item {
	it.Status = StatusNA
	it.Required = false
	it.Detail = detail
	return it
}
